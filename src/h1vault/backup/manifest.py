"""Versioned SQLite synchronization state and human-readable manifest."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from h1vault.backup.io import file_sha256, write_json

SCHEMA_VERSION = 2


class StateDatabase:
    def __init__(self, path: Path, *, initialize: bool = True) -> None:
        self.path = path
        if initialize:
            path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        if initialize:
            self._migrate()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> StateDatabase:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _migrate(self) -> None:
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)"
        )
        row = self.connection.execute("SELECT version FROM schema_version").fetchone()
        if row is None:
            self.connection.execute("INSERT INTO schema_version VALUES (0)")
            version = 0
        else:
            version = int(row[0])
        if version > SCHEMA_VERSION:
            raise RuntimeError("State database was created by a newer H1Vault version.")
        if version < 1:
            self.connection.executescript(
                """
                CREATE TABLE reports (
                    program_handle TEXT NOT NULL,
                    report_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    report_directory TEXT NOT NULL,
                    state TEXT,
                    last_activity_at TEXT,
                    list_fingerprint TEXT NOT NULL,
                    detail_fingerprint TEXT NOT NULL,
                    last_successful_sync TEXT NOT NULL,
                    last_attempted_sync TEXT NOT NULL,
                    last_error TEXT
                );
                CREATE TABLE attachments (
                    report_id TEXT NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
                    attachment_key TEXT NOT NULL,
                    attachment_id TEXT NOT NULL,
                    expected_size INTEGER,
                    local_path TEXT,
                    sha256 TEXT,
                    download_status TEXT NOT NULL,
                    last_error TEXT,
                    PRIMARY KEY(report_id, attachment_key)
                );
                CREATE INDEX reports_program ON reports(program_handle);
                UPDATE schema_version SET version = 1;
                """
            )
        if version < 2:
            columns = {
                str(item[1]) for item in self.connection.execute("PRAGMA table_info(attachments)")
            }
            additions = {
                "source": "TEXT",
                "activity_id": "TEXT",
                "remote_file_name": "TEXT",
                "content_type": "TEXT",
                "present_in_latest_response": "INTEGER NOT NULL DEFAULT 1",
                "historical_reason": "TEXT",
            }
            for name, declaration in additions.items():
                if name not in columns:
                    self.connection.execute(
                        f"ALTER TABLE attachments ADD COLUMN {name} {declaration}"
                    )
            self.connection.execute("UPDATE schema_version SET version = 2")
        self.connection.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        try:
            self.connection.execute("BEGIN")
            yield
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def report(self, report_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM reports WHERE report_id = ?", (report_id,)
        ).fetchone()
        return dict(row) if row else None

    def attachment(self, report_id: str, key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM attachments WHERE report_id = ? AND attachment_key = ?",
            (report_id, key),
        ).fetchone()
        return dict(row) if row else None

    def upsert_report(self, record: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO reports (
              program_handle, report_id, title, report_directory, state, last_activity_at,
              list_fingerprint, detail_fingerprint, last_successful_sync,
              last_attempted_sync, last_error
            ) VALUES (
              :program_handle, :report_id, :title, :report_directory, :state, :last_activity_at,
              :list_fingerprint, :detail_fingerprint, :last_successful_sync,
              :last_attempted_sync, :last_error
            )
            ON CONFLICT(report_id) DO UPDATE SET
              program_handle=excluded.program_handle, title=excluded.title,
              report_directory=excluded.report_directory, state=excluded.state,
              last_activity_at=excluded.last_activity_at,
              list_fingerprint=excluded.list_fingerprint,
              detail_fingerprint=excluded.detail_fingerprint,
              last_successful_sync=excluded.last_successful_sync,
              last_attempted_sync=excluded.last_attempted_sync, last_error=excluded.last_error
            """,
            record,
        )

    def upsert_attachment(self, record: dict[str, Any]) -> None:
        self.connection.execute(
            """
            INSERT INTO attachments (
              report_id, attachment_key, attachment_id, expected_size, local_path,
              sha256, download_status, last_error, source, activity_id, remote_file_name,
              content_type, present_in_latest_response, historical_reason
            ) VALUES (
              :report_id, :attachment_key, :attachment_id, :expected_size, :local_path,
              :sha256, :download_status, :last_error, :source, :activity_id, :remote_file_name,
              :content_type, :present_in_latest_response, :historical_reason
            )
            ON CONFLICT(report_id, attachment_key) DO UPDATE SET
              attachment_id=excluded.attachment_id, expected_size=excluded.expected_size,
              local_path=excluded.local_path, sha256=excluded.sha256,
              download_status=excluded.download_status, last_error=excluded.last_error,
              source=excluded.source, activity_id=excluded.activity_id,
              remote_file_name=excluded.remote_file_name,
              content_type=excluded.content_type,
              present_in_latest_response=excluded.present_in_latest_response,
              historical_reason=excluded.historical_reason
            """,
            record,
        )

    def reports_for_program(self, program: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM reports WHERE program_handle = ? ORDER BY report_id", (program,)
            )
        ]

    def attachments_for_report(self, report_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM attachments WHERE report_id = ? ORDER BY attachment_key",
                (report_id,),
            )
        ]

    def integrity_check(self) -> bool:
        row = self.connection.execute("PRAGMA integrity_check").fetchone()
        return bool(row and row[0] == "ok")


def write_manifest(
    root: Path,
    *,
    program: str,
    run_id: str,
    created_at: str,
    updated_at: str,
    reports: list[dict[str, Any]],
    attachments: dict[str, list[dict[str, Any]]],
    failures: list[dict[str, Any]],
) -> dict[str, Any]:
    report_items: list[dict[str, Any]] = []
    archive_files: dict[str, dict[str, Any]] = {}
    downloaded = skipped = historical = 0
    for report in reports:
        report_id = str(report["report_id"])
        items = attachments.get(report_id, [])
        report_path = str(report["report_directory"])
        report_root = root / report_path
        exported_files: dict[str, dict[str, Any]] = {}
        for name in (
            "report.raw.json",
            "report.sanitized.json",
            "report.md",
            "original-report.md",
            "timeline.json",
            "metadata.json",
        ):
            path = report_root / name
            if not path.is_file():
                continue
            record = {"sha256": file_sha256(path), "size": path.stat().st_size}
            exported_files[name] = record
            archive_files[f"{report_path}/{name}"] = record
        downloaded += sum(item.get("download_status") == "downloaded" for item in items)
        skipped += sum(item.get("download_status") == "skipped" for item in items)
        historical += sum(item.get("download_status") == "historical" for item in items)
        attachment_records = []
        for item in items:
            attachment = {
                "key": item["attachment_key"],
                "id": item["attachment_id"],
                "source": item.get("source"),
                "activity_id": item.get("activity_id"),
                "remote_file_name": item.get("remote_file_name"),
                "content_type": item.get("content_type"),
                "path": item.get("local_path"),
                "sha256": item.get("sha256"),
                "size": item.get("expected_size"),
                "status": item["download_status"],
                "skip_reason": (
                    item.get("last_error") if item["download_status"] == "skipped" else None
                ),
                "error": (item.get("last_error") if item["download_status"] == "failed" else None),
                "present_in_latest_response": bool(item.get("present_in_latest_response", 1)),
                "historical_reason": item.get("historical_reason"),
            }
            attachment_records.append(attachment)
            if (
                attachment["status"] in {"downloaded", "historical"}
                and attachment["path"]
                and attachment["sha256"]
            ):
                archive_files[str(attachment["path"])] = {
                    "sha256": attachment["sha256"],
                    "size": attachment["size"],
                }
        report_items.append(
            {
                "id": report_id,
                "program_handle": program,
                "path": report_path,
                "detail_sha256": report["detail_fingerprint"],
                "files": exported_files,
                "attachments": attachment_records,
            }
        )
    for name in ("index.md", "index.json", "program.json"):
        path = root / name
        if path.is_file():
            archive_files[name] = {"sha256": file_sha256(path), "size": path.stat().st_size}
    value = {
        "schema_version": 2,
        "h1vault_version": __import__("h1vault").__version__,
        "program_handle": program,
        "created_at": created_at,
        "last_updated_at": updated_at,
        "sync_run_id": run_id,
        "report_count": len(reports),
        "report_ids": [item["id"] for item in report_items],
        "reports": report_items,
        "archive_files": archive_files,
        "snapshot_paths": ["manifest.json", *sorted(archive_files)],
        "failed_items": failures,
        "statistics": {
            "attachments_downloaded": downloaded,
            "attachments_skipped": skipped,
            "attachments_historical": historical,
            "errors": len(failures),
        },
    }
    write_json(root / "manifest.json", value)
    return value
