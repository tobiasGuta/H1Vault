from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from h1vault.backup.manifest import StateDatabase
from h1vault.backup.snapshot import create_snapshot
from h1vault.backup.synchronizer import Synchronizer, SyncOptions
from h1vault.backup.verifier import verify_backup
from h1vault.exceptions import AttachmentDownloadError, ProgramNotFoundInReportsError
from h1vault.security.downloads import DownloadResult


class FakeClient:
    def __init__(self, reports: list[dict[str, Any]]) -> None:
        self.reports = reports
        self.detail_calls: list[str] = []
        self.fail_ids: set[str] = set()

    def iter_reports(self, page_size: int = 100):
        del page_size
        yield from self.reports

    def get_report(self, report_id: str) -> dict[str, Any]:
        self.detail_calls.append(report_id)
        if report_id in self.fail_ids:
            raise RuntimeError("detail failure")
        return next(item for item in self.reports if item["id"] == report_id)


class FakeDownloader:
    def __init__(self, fail: bool = False, content: bytes = b"abc") -> None:
        self.calls = 0
        self.fail = fail
        self.content = content

    def download(self, _url: str, destination: Path, _size: int | None) -> DownloadResult:
        self.calls += 1
        if self.fail:
            raise AttachmentDownloadError("interrupted")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.content)
        return DownloadResult(
            destination,
            hashlib.sha256(self.content).hexdigest(),
            len(self.content),
            "text/plain",
        )


def options(tmp_path: Path, **kwargs: Any) -> SyncOptions:
    return SyncOptions("example-program", tmp_path, **kwargs)


def attachment_relationship() -> dict[str, Any]:
    return {
        "attachments": {
            "data": [
                {
                    "id": "a1",
                    "type": "attachment",
                    "attributes": {
                        "file_name": "proof.txt",
                        "file_size": 3,
                        "content_type": "text/plain",
                        "expiring_url": "https://files.example/a",
                    },
                }
            ]
        }
    }


def test_initial_then_unchanged_sync_avoids_detail_and_rewrites(
    tmp_path: Path, report_factory
) -> None:
    client = FakeClient([report_factory()])
    first = Synchronizer(client, options(tmp_path)).run()
    report_file = next((tmp_path / "example-program" / "reports").glob("*/report.raw.json"))
    first_mtime = report_file.stat().st_mtime_ns
    second = Synchronizer(client, options(tmp_path)).run()
    assert (first.new_reports, second.unchanged_reports) == (1, 1)
    assert client.detail_calls == ["123"]
    assert report_file.stat().st_mtime_ns == first_mtime


@pytest.mark.parametrize("change", ["state", "last_activity_at"])
def test_list_change_triggers_refresh(tmp_path: Path, report_factory, change: str) -> None:
    report = report_factory()
    client = FakeClient([report])
    Synchronizer(client, options(tmp_path)).run()
    report["attributes"][change] = "resolved" if change == "state" else "2027-01-01T00:00:00Z"
    summary = Synchronizer(client, options(tmp_path)).run()
    assert summary.updated_reports == 1
    assert client.detail_calls == ["123", "123"]


def test_missing_local_file_triggers_repair(tmp_path: Path, report_factory) -> None:
    client = FakeClient([report_factory()])
    Synchronizer(client, options(tmp_path)).run()
    report_md = next((tmp_path / "example-program" / "reports").glob("*/report.md"))
    report_md.unlink()
    summary = Synchronizer(client, options(tmp_path)).run()
    assert summary.updated_reports == 1
    assert report_md.is_file()


def test_attachment_download_and_second_run_skip(tmp_path: Path, report_factory) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    downloader = FakeDownloader()
    first = Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    second = Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    assert first.attachments_downloaded == 1
    assert second.unchanged_reports == 1
    assert downloader.calls == 1


def test_title_change_rebases_downloaded_attachment_without_redownload(
    tmp_path: Path, report_factory
) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    downloader = FakeDownloader()
    Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    report["attributes"]["title"] = "Renamed report"
    Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    assert downloader.calls == 1
    assert verify_backup(tmp_path, "example-program").valid


def test_synchronizer_closes_only_downloader_it_creates(
    tmp_path: Path, report_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    instances: list[Any] = []

    class OwnedDownloader(FakeDownloader):
        def __init__(self, *, max_bytes: int) -> None:
            super().__init__()
            self.max_bytes = max_bytes
            self.closed = False
            instances.append(self)

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr("h1vault.backup.synchronizer.AttachmentDownloader", OwnedDownloader)
    report = report_factory(relationships=attachment_relationship())
    Synchronizer(FakeClient([report]), options(tmp_path)).run()
    assert len(instances) == 1
    assert instances[0].closed is True


def test_failed_attachment_retried_next_sync(tmp_path: Path, report_factory) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    failing = FakeDownloader(fail=True)
    Synchronizer(client, options(tmp_path), downloader=failing).run()  # type: ignore[arg-type]
    succeeding = FakeDownloader()
    summary = Synchronizer(client, options(tmp_path), downloader=succeeding).run()  # type: ignore[arg-type]
    assert succeeding.calls == 1
    assert summary.updated_reports == 1


def test_refresh_forces_detail(tmp_path: Path, report_factory) -> None:
    client = FakeClient([report_factory()])
    Synchronizer(client, options(tmp_path)).run()
    summary = Synchronizer(client, options(tmp_path, refresh=True)).run()
    assert summary.updated_reports == 1
    assert len(client.detail_calls) == 2


def test_dry_run_writes_nothing(tmp_path: Path, report_factory) -> None:
    summary = Synchronizer(FakeClient([report_factory()]), options(tmp_path, dry_run=True)).run()
    assert summary.new_reports == 1
    assert not any(tmp_path.iterdir())


def test_skip_attachments_records_metadata(tmp_path: Path, report_factory) -> None:
    report = report_factory(relationships=attachment_relationship())
    summary = Synchronizer(FakeClient([report]), options(tmp_path, include_attachments=False)).run()
    metadata = json.loads(
        next((tmp_path / "example-program" / "reports").glob("*/metadata.json")).read_text()
    )
    assert summary.attachments_skipped == 1
    assert metadata["attachments"][0]["status"] == "skipped"


def test_removed_remote_attachment_becomes_historical_and_snapshots(
    tmp_path: Path, report_factory
) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    downloader = FakeDownloader()
    Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    report["relationships"]["attachments"]["data"] = []
    Synchronizer(client, options(tmp_path, refresh=True), downloader=downloader).run()  # type: ignore[arg-type]

    root = tmp_path / "example-program"
    metadata = json.loads(next(root.glob("reports/*/metadata.json")).read_text())
    attachment = metadata["attachments"][0]
    assert attachment["status"] == "historical"
    assert attachment["present_in_latest_response"] is False
    assert "not present" in attachment["historical_reason"]
    assert (root / attachment["path"]).read_bytes() == b"abc"
    assert verify_backup(tmp_path, "example-program").valid

    destination = tmp_path.parent / f"{tmp_path.name}-historical.zip"
    snapshot, result = create_snapshot(tmp_path, "example-program", destination)
    assert result.valid
    with zipfile.ZipFile(snapshot) as archive:
        assert any(name.endswith("a1_proof.txt") for name in archive.namelist())


def test_direct_attachment_changed_to_activity_preserves_direct_history(
    tmp_path: Path, report_factory
) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    downloader = FakeDownloader()
    Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    attachment = attachment_relationship()["attachments"]["data"][0]
    report["relationships"]["attachments"]["data"] = []
    report["relationships"]["activities"]["data"] = [
        {
            "id": "activity-1",
            "type": "activity-comment",
            "attributes": {"created_at": "2026-01-03T00:00:00Z"},
            "relationships": {"attachments": {"data": [attachment]}},
        }
    ]
    Synchronizer(client, options(tmp_path, refresh=True), downloader=downloader).run()  # type: ignore[arg-type]

    root = tmp_path / "example-program"
    metadata = json.loads(next(root.glob("reports/*/metadata.json")).read_text())
    assert {(item["source"], item["status"]) for item in metadata["attachments"]} == {
        ("report", "historical"),
        ("activity", "downloaded"),
    }
    assert all((root / item["path"]).is_file() for item in metadata["attachments"])
    assert verify_backup(tmp_path, "example-program").valid


def test_skip_attachments_refresh_retains_valid_download(tmp_path: Path, report_factory) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    downloader = FakeDownloader()
    Synchronizer(client, options(tmp_path), downloader=downloader).run()  # type: ignore[arg-type]
    summary = Synchronizer(
        client,
        options(tmp_path, include_attachments=False, refresh=True),
        downloader=downloader,
    ).run()  # type: ignore[arg-type]

    metadata = json.loads(
        next((tmp_path / "example-program").glob("reports/*/metadata.json")).read_text()
    )
    assert downloader.calls == 1
    assert summary.attachments_skipped == 0
    assert metadata["attachments"][0]["status"] == "downloaded"
    assert verify_backup(tmp_path, "example-program").valid


def test_skip_after_remote_size_change_relocates_old_evidence(
    tmp_path: Path, report_factory
) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    Synchronizer(client, options(tmp_path), downloader=FakeDownloader()).run()  # type: ignore[arg-type]
    report["relationships"]["attachments"]["data"][0]["attributes"]["file_size"] = 4
    Synchronizer(
        client,
        options(tmp_path, include_attachments=False, refresh=True),
        downloader=FakeDownloader(content=b"unused"),
    ).run()  # type: ignore[arg-type]

    root = tmp_path / "example-program"
    metadata = json.loads(next(root.glob("reports/*/metadata.json")).read_text())
    by_status = {item["status"]: item for item in metadata["attachments"]}
    assert set(by_status) == {"historical", "skipped"}
    assert (root / by_status["historical"]["path"]).read_bytes() == b"abc"
    assert not (root / by_status["skipped"]["path"]).exists()
    assert verify_backup(tmp_path, "example-program").valid


@pytest.mark.parametrize(
    ("changed_field", "changed_value", "content"),
    [("file_name", "renamed.txt", b"xyz"), ("file_size", 4, b"abcd")],
)
def test_attachment_filename_or_size_change_preserves_previous_evidence(
    tmp_path: Path,
    report_factory,
    changed_field: str,
    changed_value: str | int,
    content: bytes,
) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    Synchronizer(client, options(tmp_path), downloader=FakeDownloader()).run()  # type: ignore[arg-type]
    report["relationships"]["attachments"]["data"][0]["attributes"][changed_field] = changed_value
    Synchronizer(
        client,
        options(tmp_path, refresh=True),
        downloader=FakeDownloader(content=content),
    ).run()  # type: ignore[arg-type]

    root = tmp_path / "example-program"
    metadata = json.loads(next(root.glob("reports/*/metadata.json")).read_text())
    by_status = {item["status"]: item for item in metadata["attachments"]}
    assert set(by_status) == {"historical", "downloaded"}
    assert (root / by_status["historical"]["path"]).read_bytes() == b"abc"
    assert (root / by_status["downloaded"]["path"]).read_bytes() == content
    assert verify_backup(tmp_path, "example-program").valid


def test_repeated_filename_changes_with_same_bytes_keep_every_version(
    tmp_path: Path, report_factory
) -> None:
    report = report_factory(relationships=attachment_relationship())
    client = FakeClient([report])
    for index, name in enumerate(("proof.txt", "second.txt", "third.txt")):
        report["relationships"]["attachments"]["data"][0]["attributes"]["file_name"] = name
        Synchronizer(
            client,
            options(tmp_path, refresh=index > 0),
            downloader=FakeDownloader(),
        ).run()  # type: ignore[arg-type]

    root = tmp_path / "example-program"
    metadata = json.loads(next(root.glob("reports/*/metadata.json")).read_text())
    assert [item["status"] for item in metadata["attachments"]].count("historical") == 2
    assert len({item["key"] for item in metadata["attachments"]}) == 3
    assert all((root / item["path"]).is_file() for item in metadata["attachments"])
    assert verify_backup(tmp_path, "example-program").valid


def test_one_report_failure_continues_by_default(tmp_path: Path, report_factory) -> None:
    client = FakeClient([report_factory("1"), report_factory("2")])
    client.fail_ids.add("1")
    summary = Synchronizer(client, options(tmp_path)).run()
    assert len(summary.errors) == 1
    assert summary.new_reports == 1


def test_fail_fast_stops(tmp_path: Path, report_factory) -> None:
    client = FakeClient([report_factory("1"), report_factory("2")])
    client.fail_ids.add("1")
    with pytest.raises(RuntimeError, match="detail failure"):
        Synchronizer(client, options(tmp_path, fail_fast=True)).run()
    assert client.detail_calls == ["1"]


def test_no_program_is_actionable(tmp_path: Path, report_factory) -> None:
    with pytest.raises(ProgramNotFoundInReportsError, match="programs list"):
        Synchronizer(FakeClient([report_factory(program="other")]), options(tmp_path)).run()


def test_index_and_atomic_manifest_created(tmp_path: Path, report_factory) -> None:
    Synchronizer(FakeClient([report_factory()]), options(tmp_path)).run()
    root = tmp_path / "example-program"
    assert (root / "index.md").is_file()
    assert json.loads((root / "index.json").read_text())["total_reports"] == 1
    assert json.loads((root / "manifest.json").read_text())["report_ids"] == ["123"]
    assert not list(root.glob("*.tmp"))


def test_database_update_follows_successful_export(
    tmp_path: Path, report_factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_export(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("write failed")

    monkeypatch.setattr("h1vault.backup.synchronizer.export_report", fail_export)
    summary = Synchronizer(FakeClient([report_factory()]), options(tmp_path)).run()
    assert len(summary.errors) == 1
    with StateDatabase(
        tmp_path / "example-program" / "state.sqlite3", initialize=False
    ) as database:
        assert database.report("123") is None


def test_schema_one_database_migrates_attachment_provenance_columns(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version VALUES (1);
            CREATE TABLE attachments (
                report_id TEXT NOT NULL,
                attachment_key TEXT NOT NULL,
                attachment_id TEXT NOT NULL,
                expected_size INTEGER,
                local_path TEXT,
                sha256 TEXT,
                download_status TEXT NOT NULL,
                last_error TEXT,
                PRIMARY KEY(report_id, attachment_key)
            );
            """
        )
    with StateDatabase(path) as database:
        version = database.connection.execute("SELECT version FROM schema_version").fetchone()[0]
        columns = {row[1] for row in database.connection.execute("PRAGMA table_info(attachments)")}
    assert version == 2
    assert {
        "source",
        "activity_id",
        "remote_file_name",
        "content_type",
        "present_in_latest_response",
        "historical_reason",
    } <= columns
