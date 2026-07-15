from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from h1vault.backup.snapshot import create_snapshot
from h1vault.backup.synchronizer import Synchronizer, SyncOptions
from h1vault.backup.verifier import verify_backup
from h1vault.exceptions import BackupIntegrityError
from tests.test_sync import FakeClient


def create_backup(tmp_path: Path, report_factory) -> Path:
    Synchronizer(FakeClient([report_factory()]), SyncOptions("example-program", tmp_path)).run()
    return tmp_path / "example-program"


def test_valid_backup(tmp_path: Path, report_factory) -> None:
    create_backup(tmp_path, report_factory)
    result = verify_backup(tmp_path, "example-program")
    assert result.valid
    assert result.checked_reports == 1


@pytest.mark.parametrize("filename", ["report.md", "report.json", "timeline.json"])
def test_missing_report_file_detected(tmp_path: Path, report_factory, filename: str) -> None:
    root = create_backup(tmp_path, report_factory)
    next(root.glob(f"reports/*/{filename}")).unlink()
    result = verify_backup(tmp_path, "example-program")
    assert not result.valid
    assert any(filename in error for error in result.errors)


def test_invalid_json_detected(tmp_path: Path, report_factory) -> None:
    root = create_backup(tmp_path, report_factory)
    path = next(root.glob("reports/*/timeline.json"))
    path.write_text("not json")
    assert not verify_backup(tmp_path, "example-program").valid


def test_temporary_url_and_authorization_leak_detected(tmp_path: Path, report_factory) -> None:
    root = create_backup(tmp_path, report_factory)
    path = next(root.glob("reports/*/report.json"))
    value = json.loads(path.read_text())
    value["data"]["attributes"]["expiring_url"] = "https://x/?signature=secret"
    value["data"]["attributes"]["notes"] = "Authorization: Basic leaked"
    path.write_text(json.dumps(value))
    result = verify_backup(tmp_path, "example-program")
    assert not result.valid
    assert any("temporary" in error.lower() for error in result.errors)
    assert any("Authorization" in error for error in result.errors)


def test_configured_token_leak_detected(tmp_path: Path, report_factory) -> None:
    root = create_backup(tmp_path, report_factory)
    (root / "index.md").write_text("secret-token")
    result = verify_backup(tmp_path, "example-program", configured_token="secret-token")
    assert not result.valid


def test_stale_part_detected(tmp_path: Path, report_factory) -> None:
    root = create_backup(tmp_path, report_factory)
    (root / "stale.part").write_bytes(b"x")
    assert not verify_backup(tmp_path, "example-program").valid


def test_database_manifest_mismatch_detected(tmp_path: Path, report_factory) -> None:
    root = create_backup(tmp_path, report_factory)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["reports"] = []
    manifest["report_ids"] = []
    (root / "manifest.json").write_text(json.dumps(manifest))
    result = verify_backup(tmp_path, "example-program")
    assert not result.valid
    assert any("Database" in error for error in result.errors)


def test_snapshot_excludes_database_and_includes_manifest(tmp_path: Path, report_factory) -> None:
    create_backup(tmp_path, report_factory)
    destination = tmp_path.parent / f"{tmp_path.name}-snapshot.zip"
    path, result = create_snapshot(tmp_path, "example-program", destination)
    assert result.valid
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
    assert any(name.endswith("manifest.json") for name in names)
    assert not any(name.endswith("state.sqlite3") for name in names)


def test_snapshot_refuses_invalid_backup_without_force(tmp_path: Path, report_factory) -> None:
    root = create_backup(tmp_path, report_factory)
    (root / "manifest.json").unlink()
    with pytest.raises(BackupIntegrityError):
        create_snapshot(tmp_path, "example-program", tmp_path.parent / "invalid.zip")
