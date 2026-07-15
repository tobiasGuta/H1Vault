"""SQLite-backed, idempotent program synchronization."""

from __future__ import annotations

import json
import logging
import os
import shutil
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from h1vault.api.client import HackerOneClient
from h1vault.api.models import (
    DetailedReportResponse,
    filter_program,
    program_handle,
    relationship_data,
)
from h1vault.backup.exporter import choose_report_directory, export_report
from h1vault.backup.io import atomic_write, file_sha256, fingerprint, write_json
from h1vault.backup.manifest import StateDatabase, write_manifest
from h1vault.backup.renderer import (
    attributes_of,
    bounty_total,
    extract_attachments,
    relationship_label,
)
from h1vault.exceptions import (
    AttachmentDownloadError,
    AttachmentTooLargeError,
    ExpiredAttachmentURLError,
    ProgramNotFoundInReportsError,
)
from h1vault.security.downloads import AttachmentDownloader
from h1vault.security.filenames import attachment_filename, ensure_within, safe_filename
from h1vault.security.redaction import redact_data

LOGGER = logging.getLogger(__name__)


@dataclass
class SyncOptions:
    program: str
    output: Path
    include_attachments: bool = True
    max_attachment_size_mb: int = 1024
    refresh: bool = False
    dry_run: bool = False
    fail_fast: bool = False


@dataclass
class SyncSummary:
    run_id: str
    program: str
    backup: str
    reports_discovered: int = 0
    new_reports: int = 0
    updated_reports: int = 0
    unchanged_reports: int = 0
    attachments_downloaded: int = 0
    attachments_skipped: int = 0
    errors: list[dict[str, str]] = field(default_factory=list)
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["error_count"] = len(self.errors)
        return value


class Synchronizer:
    def __init__(
        self,
        client: HackerOneClient,
        options: SyncOptions,
        *,
        downloader: AttachmentDownloader | None = None,
        clock: Any = None,
        progress: Callable[[str, int], None] | None = None,
    ) -> None:
        self.client = client
        self.options = options
        self.clock = clock or (lambda: datetime.now(UTC))
        self.program_root = options.output / safe_filename(options.program, fallback="program")
        self.reports_root = self.program_root / "reports"
        self.downloader = downloader
        self._owns_downloader = False
        self.progress = progress

    def run(self) -> SyncSummary:
        """Run one synchronization and close only downloader resources owned here."""
        try:
            return self._run()
        finally:
            if self._owns_downloader and self.downloader is not None:
                self.downloader.close()

    def _run(self) -> SyncSummary:
        run_id = str(uuid.uuid4())
        summary = SyncSummary(
            run_id, self.options.program, str(self.program_root), dry_run=self.options.dry_run
        )
        list_reports = list(self.client.iter_reports())
        matching = filter_program(list_reports, self.options.program)
        if not matching:
            raise ProgramNotFoundInReportsError(
                "No reports owned by this account were found for program handle "
                f'"{self.options.program}". '
                "Run `h1vault programs list` to inspect handles represented in your report history."
            )
        summary.reports_discovered = len(matching)
        self._progress("reports_total", len(matching))
        if self.options.dry_run:
            self._dry_run(matching, summary)
            return summary
        self.program_root.mkdir(parents=True, exist_ok=True)
        self.reports_root.mkdir(parents=True, exist_ok=True)
        now = self.clock().isoformat()
        database_path = self.program_root / "state.sqlite3"
        with StateDatabase(database_path) as state:
            created_at = self._manifest_created_at(now)
            for listed in matching:
                try:
                    self._sync_report(listed, state, summary, now)
                except Exception as exc:
                    report_id = str(listed.get("id", "unknown"))
                    LOGGER.error("Report %s failed: %s", report_id, exc)
                    summary.errors.append({"report_id": report_id, "error": str(exc)})
                    if self.options.fail_fast:
                        raise
                finally:
                    self._progress("report_complete", 1)
            records = state.reports_for_program(self.options.program)
            attachment_map = {
                str(row["report_id"]): state.attachments_for_report(str(row["report_id"]))
                for row in records
            }
            changed = summary.new_reports + summary.updated_reports > 0 or bool(summary.errors)
            if changed or not (self.program_root / "index.json").exists():
                self._write_indexes(records, now, summary)
            first_program = relationship_data(matching[0], "program")
            write_json(
                self.program_root / "program.json",
                {"schema_version": 1, "data": redact_data(first_program)},
            )
            write_manifest(
                self.program_root,
                program=self.options.program,
                run_id=run_id,
                created_at=created_at,
                updated_at=now,
                reports=records,
                attachments=attachment_map,
                failures=summary.errors,
            )
        return summary

    def _dry_run(self, reports: list[dict[str, Any]], summary: SyncSummary) -> None:
        db_path = self.program_root / "state.sqlite3"
        if not db_path.exists():
            summary.new_reports = len(reports)
            return
        with StateDatabase(db_path, initialize=False) as state:
            for item in reports:
                current = state.report(str(item["id"]))
                list_hash = fingerprint(redact_data(item))
                if current is None:
                    summary.new_reports += 1
                elif self.options.refresh or current["list_fingerprint"] != list_hash:
                    summary.updated_reports += 1
                else:
                    summary.unchanged_reports += 1

    def _sync_report(
        self,
        listed: dict[str, Any],
        state: StateDatabase,
        summary: SyncSummary,
        now: str,
    ) -> None:
        report_id = str(listed["id"])
        current = state.report(report_id)
        list_hash = fingerprint(redact_data(listed))
        needs_detail = self.options.refresh or current is None
        if current is not None:
            report_dir = self.program_root / str(current["report_directory"])
            required = (
                "report.md",
                "report.raw.json",
                "report.sanitized.json",
                "original-report.md",
                "timeline.json",
                "metadata.json",
            )
            missing = any(not (report_dir / name).is_file() for name in required)
            attachment_bad = any(
                item.get("download_status") == "failed"
                or item.get("source") is None
                or (
                    item.get("download_status") in {"downloaded", "historical"}
                    and (
                        not item.get("local_path")
                        or not (self.program_root / str(item["local_path"])).is_file()
                    )
                )
                for item in state.attachments_for_report(report_id)
            )
            needs_detail = (
                needs_detail
                or missing
                or attachment_bad
                or current["list_fingerprint"] != list_hash
            )
        if not needs_detail:
            summary.unchanged_reports += 1
            return
        response = self._fetch_detail(report_id)
        detail = response.resource
        detail_handle = program_handle(detail)
        if (
            detail_handle is not None
            and detail_handle.strip().casefold() != self.options.program.strip().casefold()
        ):
            raise ValueError(
                "Detailed report program does not match the locally selected exact handle."
            )
        attrs = attributes_of(detail)
        title = str(attrs.get("title") or "untitled")
        directory = choose_report_directory(self.reports_root, report_id, title)
        attachment_records, refreshed_response = self._process_attachments(
            detail, directory, report_id, state, summary
        )
        final_response = refreshed_response or response
        detail = final_response.resource
        result = export_report(
            detail,
            self.reports_root,
            raw_document=final_response.raw_document,
            program=self.options.program,
            synchronized_at=now,
            attachment_records=attachment_records,
        )
        relative_dir = result.directory.relative_to(self.program_root).as_posix()
        with state.transaction():
            state.upsert_report(
                {
                    "program_handle": self.options.program,
                    "report_id": report_id,
                    "title": title,
                    "report_directory": relative_dir,
                    "state": attrs.get("state"),
                    "last_activity_at": attrs.get("last_activity_at"),
                    "list_fingerprint": list_hash,
                    "detail_fingerprint": result.report_fingerprint,
                    "last_successful_sync": now,
                    "last_attempted_sync": now,
                    "last_error": None,
                }
            )
            for record in attachment_records:
                state.upsert_attachment(
                    {
                        "report_id": report_id,
                        "attachment_key": record["key"],
                        "attachment_id": record["id"],
                        "expected_size": record.get("size"),
                        "local_path": record.get("path"),
                        "sha256": record.get("sha256"),
                        "download_status": record["status"],
                        "last_error": (
                            record.get("skip_reason")
                            or record.get("error")
                            or record.get("historical_reason")
                        ),
                        "source": record.get("source"),
                        "activity_id": record.get("activity_id"),
                        "remote_file_name": record.get("remote_file_name"),
                        "content_type": record.get("content_type"),
                        "present_in_latest_response": int(
                            bool(record.get("present_in_latest_response", True))
                        ),
                        "historical_reason": record.get("historical_reason"),
                    }
                )
        if current is None:
            summary.new_reports += 1
        else:
            summary.updated_reports += 1

    def _process_attachments(
        self,
        detail: dict[str, Any],
        directory: Path,
        report_id: str,
        state: StateDatabase,
        summary: SyncSummary,
    ) -> tuple[list[dict[str, Any]], DetailedReportResponse | None]:
        records: list[dict[str, Any]] = []
        refreshed: DetailedReportResponse | None = None
        attachments = extract_attachments(detail)
        previous_items = {
            str(item["attachment_key"]): item for item in state.attachments_for_report(report_id)
        }
        for stored in previous_items.values():
            self._rebase_previous_path(stored, directory)
        seen_keys: set[str] = set()
        self._progress("attachments_total", len(attachments))
        for item in attachments:
            attrs = attributes_of(item)
            attachment_id = str(item["id"])
            source = str(item.get("_source", "report"))
            activity_id = str(item.get("_activity_id", ""))
            key = (
                f"activity:{activity_id}:{attachment_id}"
                if source == "activity"
                else f"report:{attachment_id}"
            )
            seen_keys.add(key)
            target_dir = (
                directory / "attachments" / "activities" / safe_filename(activity_id)
                if source == "activity"
                else directory / "attachments" / "report"
            )
            remote_file_name = str(attrs.get("file_name") or "unnamed")
            target = target_dir / attachment_filename(attachment_id, remote_file_name)
            relative = target.relative_to(self.program_root).as_posix()
            size = _optional_int(attrs.get("file_size"))
            base = {
                "key": key,
                "id": attachment_id,
                "source": source,
                "activity_id": activity_id or None,
                "remote_file_name": remote_file_name,
                "path": relative,
                "content_type": attrs.get("content_type"),
                "size": size,
                "sha256": None,
                "status": "pending",
                "skip_reason": None,
                "error": None,
                "present_in_latest_response": True,
                "historical_reason": None,
            }
            previous = previous_items.get(key)
            if previous and self._valid_existing(previous, size, relative, remote_file_name):
                base.update(status="downloaded", sha256=previous["sha256"])
                records.append(base)
                self._progress("attachment_complete", 1)
                continue
            if previous and self._valid_archived(previous):
                records.append(
                    self._historical_record(
                        previous,
                        directory,
                        reason="attachment metadata changed in latest API response",
                        replacing_path=relative,
                    )
                )
            if not self.options.include_attachments:
                base.update(status="skipped", skip_reason="attachments disabled by configuration")
                summary.attachments_skipped += 1
                records.append(base)
                self._progress("attachment_complete", 1)
                continue
            max_bytes = self.options.max_attachment_size_mb * 1024 * 1024
            if size is not None and size > max_bytes:
                base.update(
                    status="skipped", skip_reason=f"declared size exceeds {max_bytes} bytes"
                )
                summary.attachments_skipped += 1
                records.append(base)
                self._progress("attachment_complete", 1)
                continue
            url = attrs.get("expiring_url")
            if not isinstance(url, str) or not url:
                base.update(status="skipped", skip_reason="temporary download URL is missing")
                summary.attachments_skipped += 1
                records.append(base)
                self._progress("attachment_complete", 1)
                continue
            if self.downloader is None:
                self.downloader = AttachmentDownloader(max_bytes=max_bytes)
                self._owns_downloader = True
            try:
                result = self.downloader.download(url, target, size)
            except ExpiredAttachmentURLError as exc:
                refreshed = self._fetch_detail(report_id)
                refreshed_item = _find_attachment(refreshed.resource, key)
                refreshed_url = (
                    attributes_of(refreshed_item).get("expiring_url") if refreshed_item else None
                )
                if not isinstance(refreshed_url, str) or not refreshed_url:
                    raise AttachmentDownloadError(
                        f"Attachment {attachment_id} expired and no refreshed URL was available."
                    ) from exc
                result = self.downloader.download(refreshed_url, target, size)
            except AttachmentTooLargeError as exc:
                base.update(status="skipped", skip_reason=str(exc))
                summary.attachments_skipped += 1
                records.append(base)
                self._progress("attachment_complete", 1)
                continue
            except AttachmentDownloadError as exc:
                base.update(status="failed", error=str(exc))
                summary.errors.append(
                    {
                        "report_id": report_id,
                        "attachment_id": attachment_id,
                        "error": str(exc),
                    }
                )
                records.append(base)
                self._progress("attachment_complete", 1)
                continue
            base.update(status="downloaded", sha256=result.sha256, size=result.size)
            summary.attachments_downloaded += 1
            records.append(base)
            self._progress("attachment_complete", 1)
        record_keys = {str(item["key"]) for item in records}
        for key, previous in previous_items.items():
            if key in seen_keys or key in record_keys:
                continue
            if key.startswith("historical:"):
                records.append(self._record_from_database(previous))
            else:
                records.append(
                    self._historical_record(
                        previous,
                        directory,
                        reason="not present in latest API response",
                    )
                )
        return records, refreshed

    def _progress(self, event: str, amount: int) -> None:
        if self.progress is not None:
            self.progress(event, amount)

    def _fetch_detail(self, report_id: str) -> DetailedReportResponse:
        method = getattr(self.client, "get_report_response", None)
        if callable(method):
            response = method(report_id)
            if isinstance(response, DetailedReportResponse):
                return response
        resource = self.client.get_report(report_id)
        return DetailedReportResponse(raw_document={"data": resource}, resource=resource)

    def _valid_existing(
        self,
        previous: dict[str, Any],
        expected_size: int | None,
        relative: str,
        remote_file_name: str,
    ) -> bool:
        if previous.get("expected_size") != expected_size:
            return False
        stored_name = previous.get("remote_file_name")
        if stored_name is not None and stored_name != remote_file_name:
            return False
        if previous.get("download_status") not in {"downloaded", "historical"}:
            return False
        path = self.program_root / relative
        return bool(
            path.is_file()
            and previous.get("sha256")
            and file_sha256(path) == str(previous["sha256"])
        )

    def _valid_archived(self, previous: dict[str, Any]) -> bool:
        if previous.get("download_status") not in {"downloaded", "historical"}:
            return False
        if not previous.get("local_path"):
            return False
        path = self.program_root / str(previous["local_path"])
        if not path.is_file() or not previous.get("sha256"):
            return False
        return file_sha256(path) == str(previous["sha256"])

    def _rebase_previous_path(self, previous: dict[str, Any], directory: Path) -> None:
        raw_path = previous.get("local_path")
        if not isinstance(raw_path, str):
            return
        current = self.program_root / raw_path
        parts = Path(raw_path).parts
        if current.exists() or len(parts) < 3 or parts[0] != "reports":
            return
        candidate = directory.joinpath(*parts[2:])
        if candidate.is_file():
            previous["local_path"] = candidate.relative_to(self.program_root).as_posix()

    def _historical_record(
        self,
        previous: dict[str, Any],
        directory: Path,
        *,
        reason: str,
        replacing_path: str | None = None,
    ) -> dict[str, Any]:
        key = str(previous["attachment_key"])
        local_path = previous.get("local_path")
        sha256 = previous.get("sha256")
        if replacing_path is not None:
            version_id = fingerprint(previous)[:16]
            key = f"historical:{key}:{version_id}"
            if local_path == replacing_path and self._valid_archived(previous):
                source = self.program_root / str(local_path)
                history_name = f"{version_id}_{Path(str(local_path)).name}"
                history_target = (
                    directory
                    / "attachments"
                    / "historical"
                    / safe_filename(str(previous["attachment_id"]))
                    / history_name
                )
                self._copy_archived_file(source, history_target)
                if file_sha256(history_target) != str(sha256):
                    raise OSError("Historical attachment relocation failed integrity validation.")
                source.unlink()
                local_path = history_target.relative_to(self.program_root).as_posix()
        return {
            "key": key,
            "id": str(previous["attachment_id"]),
            "source": previous.get("source") or _source_from_key(str(previous["attachment_key"])),
            "activity_id": previous.get("activity_id"),
            "remote_file_name": previous.get("remote_file_name"),
            "content_type": previous.get("content_type"),
            "path": local_path,
            "size": previous.get("expected_size"),
            "sha256": sha256,
            "status": "historical",
            "skip_reason": None,
            "error": None,
            "present_in_latest_response": False,
            "historical_reason": reason,
        }

    def _record_from_database(self, previous: dict[str, Any]) -> dict[str, Any]:
        return {
            "key": str(previous["attachment_key"]),
            "id": str(previous["attachment_id"]),
            "source": previous.get("source") or _source_from_key(str(previous["attachment_key"])),
            "activity_id": previous.get("activity_id"),
            "remote_file_name": previous.get("remote_file_name"),
            "content_type": previous.get("content_type"),
            "path": previous.get("local_path"),
            "size": previous.get("expected_size"),
            "sha256": previous.get("sha256"),
            "status": str(previous["download_status"]),
            "skip_reason": None,
            "error": None,
            "present_in_latest_response": bool(previous.get("present_in_latest_response", 0)),
            "historical_reason": previous.get("historical_reason") or previous.get("last_error"),
        }

    def _copy_archived_file(self, source: Path, target: Path) -> None:
        source = ensure_within(source, self.program_root)
        target = ensure_within(target, self.program_root)
        if target.is_file() and file_sha256(target) == file_sha256(source):
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")
        try:
            with source.open("rb") as reader, temporary.open("xb") as writer:
                shutil.copyfileobj(reader, writer)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def _write_indexes(self, records: list[dict[str, Any]], now: str, summary: SyncSummary) -> None:
        entries: list[dict[str, Any]] = []
        state_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        total_bounty = 0.0
        for record in records:
            report_file = self.program_root / record["report_directory"] / "report.raw.json"
            try:
                report = json.loads(report_file.read_text(encoding="utf-8"))["data"]
            except (OSError, ValueError, KeyError, TypeError):
                continue
            attrs = attributes_of(report)
            state = str(attrs.get("state") or "unknown")
            severity = relationship_label(report, "severity", "rating", "severity_rating")
            state_counts[state] = state_counts.get(state, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            bounty = bounty_total(report)
            if bounty is not None:
                total_bounty += float(bounty)
            metadata_file = report_file.parent / "metadata.json"
            metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
            entries.append(
                {
                    "report_id": str(report["id"]),
                    "title": str(attrs.get("title") or "Untitled"),
                    "state": state,
                    "severity": severity,
                    "submitted_at": attrs.get("submitted_at") or attrs.get("created_at"),
                    "last_activity_at": attrs.get("last_activity_at"),
                    "bounty_total": bounty,
                    "attachment_count": len(metadata.get("attachments", [])),
                    "local_path": record["report_directory"],
                }
            )
        entries.sort(key=lambda x: str(x.get("submitted_at") or ""), reverse=True)
        index = {
            "schema_version": 1,
            "program_handle": self.options.program,
            "total_reports": len(entries),
            "state_counts": state_counts,
            "severity_counts": severity_counts,
            "total_known_bounty_amount": f"{total_bounty:.2f}",
            "last_synchronization_time": now,
            "downloaded_attachments": summary.attachments_downloaded,
            "skipped_attachments": summary.attachments_skipped,
            "synchronization_errors": len(summary.errors),
            "reports": entries,
        }
        write_json(self.program_root / "index.json", index)
        lines = [
            f"# H1Vault index: {self.options.program}",
            "",
            f"- Total reports: {len(entries)}",
            f"- State counts: {json.dumps(state_counts, sort_keys=True)}",
            f"- Severity counts: {json.dumps(severity_counts, sort_keys=True)}",
            f"- Total known bounty amount: {total_bounty:.2f}",
            f"- Last synchronization time: {now}",
            f"- Downloaded attachments: {summary.attachments_downloaded}",
            f"- Skipped attachments: {summary.attachments_skipped}",
            f"- Synchronization errors: {len(summary.errors)}",
            "",
            "| Report ID | Title | State | Severity | Submitted | Last activity | "
            "Bounty | Attachments | Local path |",
            "|---|---|---|---|---|---|---:|---:|---|",
        ]
        for entry in entries:
            clean_title = entry["title"].replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {entry['report_id']} | {clean_title} | {entry['state']} | "
                f"{entry['severity']} | "
                f"{entry['submitted_at'] or ''} | {entry['last_activity_at'] or ''} | "
                f"{entry['bounty_total'] or ''} | {entry['attachment_count']} | "
                f"[{entry['local_path']}]({entry['local_path']}/report.md) |"
            )
        atomic_write(self.program_root / "index.md", ("\n".join(lines) + "\n").encode())

    def _manifest_created_at(self, default: str) -> str:
        path = self.program_root / "manifest.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return str(value.get("created_at") or default)
        except (OSError, ValueError, TypeError):
            return default


def _optional_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _find_attachment(report: dict[str, Any], key: str) -> dict[str, Any] | None:
    for item in extract_attachments(report):
        attachment_id = str(item.get("id"))
        source = item.get("_source")
        activity = item.get("_activity_id")
        candidate = (
            f"activity:{activity}:{attachment_id}"
            if source == "activity"
            else f"report:{attachment_id}"
        )
        if candidate == key:
            return item
    return None


def _source_from_key(key: str) -> str:
    value = key
    while value.startswith("historical:"):
        value = value.removeprefix("historical:")
    return "activity" if value.startswith("activity:") else "report"
