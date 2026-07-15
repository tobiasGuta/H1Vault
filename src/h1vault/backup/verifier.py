"""Integrity, containment, and generated-output confidentiality verification."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from h1vault.api.models import normalize_handle, program_handle
from h1vault.backup.io import file_sha256, fingerprint
from h1vault.backup.manifest import StateDatabase
from h1vault.exceptions import UnsafeAttachmentPathError
from h1vault.security.filenames import ensure_within, safe_filename
from h1vault.security.redaction import REDACTED_URL

AUTHORIZATION_RE = re.compile(r"(?i)authorization\s*[:=]\s*(?:basic|bearer)\s+(?!<redacted>)\S+")
TEMPORARY_URL_RE = re.compile(
    r"https://[^\s\"']+[?&](?:x-amz-|signature=|sig=|credential=|token=)", re.IGNORECASE
)
REPORT_FILES = {
    "report.raw.json",
    "report.sanitized.json",
    "report.md",
    "original-report.md",
    "timeline.json",
    "metadata.json",
}
EVIDENCE_FILES = {"report.raw.json", "original-report.md"}


@dataclass
class VerificationResult:
    program: str
    backup: str
    valid: bool = True
    checked_reports: int = 0
    checked_attachments: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    manifest_sha256: str | None = None
    archive_files: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add_error(self, message: str) -> None:
        self.valid = False
        self.errors.append(message)

    def to_dict(self) -> dict[str, Any]:
        return {
            "program": self.program,
            "backup": self.backup,
            "valid": self.valid,
            "checked_reports": self.checked_reports,
            "checked_attachments": self.checked_attachments,
            "errors": self.errors,
            "warnings": self.warnings,
        }


def verify_backup(
    output: Path, program: str, *, configured_token: str | None = None
) -> VerificationResult:
    root = output / safe_filename(program, fallback="program")
    result = VerificationResult(program, str(root))
    manifest_path = root / "manifest.json"
    try:
        _require_regular(manifest_path, root)
        result.manifest_sha256 = file_sha256(manifest_path)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnsafeAttachmentPathError) as exc:
        result.add_error(f"Manifest is missing, unsafe, or invalid JSON: {exc}")
        return result
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 2:
        result.add_error("Manifest must use supported schema version 2.")
        return result
    if manifest.get("program_handle") != program:
        result.add_error("Manifest program handle does not match the requested program.")
    raw_archive = manifest.get("archive_files")
    if not isinstance(raw_archive, dict):
        result.add_error("Manifest archive_files must be an object.")
        return result
    result.archive_files = {
        str(path): record for path, record in raw_archive.items() if isinstance(record, dict)
    }
    if len(result.archive_files) != len(raw_archive):
        result.add_error("Manifest contains malformed archive file records.")
    expected_snapshot_paths = ["manifest.json", *sorted(result.archive_files)]
    if manifest.get("snapshot_paths") != expected_snapshot_paths:
        result.add_error("Manifest snapshot_paths does not match its explicit archive file set.")

    manifest_ids: set[str] = set()
    declared_report_dirs: set[str] = set()
    derived_archive: dict[str, dict[str, Any]] = {}
    reports = manifest.get("reports")
    if not isinstance(reports, list):
        result.add_error("Manifest reports must be an array.")
        reports = []
    if manifest.get("report_count") != len(reports):
        result.add_error("Manifest report_count does not match its reports array.")
    for report in reports:
        if not isinstance(report, dict):
            result.add_error("Manifest contains a malformed report record.")
            continue
        _verify_report(
            root, program, report, result, manifest_ids, declared_report_dirs, derived_archive
        )
    expected_ids = [str(item.get("id")) for item in reports if isinstance(item, dict)]
    if manifest.get("report_ids") != expected_ids:
        result.add_error("Manifest report_ids does not match its reports array.")

    for name in ("index.md", "index.json", "program.json"):
        if name in result.archive_files:
            derived_archive[name] = result.archive_files[name]
            _verify_file_record(root, name, result.archive_files[name], result)
        else:
            result.add_error(f"Manifest does not track required program file {name}.")
    if set(result.archive_files) != set(derived_archive):
        missing = sorted(set(derived_archive) - set(result.archive_files))
        extra = sorted(set(result.archive_files) - set(derived_archive))
        result.add_error(f"Manifest archive file set mismatch; missing={missing}, extra={extra}.")

    _verify_report_directories(root, declared_report_dirs, result)
    _verify_database(root, program, manifest_ids, result)
    allowed = {"manifest.json", "state.sqlite3", *result.archive_files}
    _verify_no_untracked_files(root, allowed, result)
    _scan_generated_text(root, result.archive_files, configured_token, result)
    return result


def _verify_report(
    root: Path,
    program: str,
    report: dict[str, Any],
    result: VerificationResult,
    manifest_ids: set[str],
    declared_report_dirs: set[str],
    derived_archive: dict[str, dict[str, Any]],
) -> None:
    report_id = str(report.get("id"))
    if report.get("program_handle") != program:
        result.add_error(f"Report {report_id} manifest program handle is inconsistent.")
    manifest_ids.add(report_id)
    report_path = str(report.get("path", ""))
    declared_report_dirs.add(report_path)
    try:
        report_dir = ensure_within(root / report_path, root)
    except Exception as exc:
        result.add_error(f"Report {report_id} has an unsafe path: {exc}")
        return
    files = report.get("files")
    if not isinstance(files, dict) or set(files) != REPORT_FILES:
        result.add_error(f"Report {report_id} does not declare the exact required export file set.")
        return
    parsed: dict[str, Any] = {}
    for name, record in files.items():
        relative = f"{report_path}/{name}"
        if not isinstance(record, dict):
            result.add_error(f"Report {report_id} has a malformed hash record for {name}.")
            continue
        derived_archive[relative] = record
        _verify_file_record(root, relative, record, result)
        if name.endswith(".json"):
            try:
                parsed[name] = json.loads((report_dir / name).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                result.add_error(f"Report {report_id} has invalid {name}: {exc}")
    raw_data = _document_data(parsed.get("report.raw.json"))
    sanitized_data = _document_data(parsed.get("report.sanitized.json"))
    metadata = parsed.get("metadata.json")
    if raw_data is None:
        result.add_error(f"Report {report_id} raw JSON document is malformed.")
    else:
        if str(raw_data.get("id")) != report_id:
            result.add_error(f"Report {report_id} raw JSON contains a different report ID.")
        raw_program = program_handle(raw_data)
        if raw_program is None or normalize_handle(raw_program) != normalize_handle(program):
            result.add_error(f"Report {report_id} raw JSON contains a different program handle.")
        if fingerprint(raw_data) != report.get("detail_sha256"):
            result.add_error(f"Report {report_id} detailed-response fingerprint mismatch.")
        _inspect_value(raw_data, f"report {report_id}/report.raw.json", result, secrets=False)
    if sanitized_data is None:
        result.add_error(f"Report {report_id} sanitized JSON document is malformed.")
    else:
        _inspect_value(
            sanitized_data, f"report {report_id}/report.sanitized.json", result, secrets=True
        )
    if not isinstance(metadata, dict):
        result.add_error(f"Report {report_id} metadata.json must be an object.")
        metadata = {}
    if str(metadata.get("report_id")) != report_id or metadata.get("program_handle") != program:
        result.add_error(f"Report {report_id} metadata identity does not match the manifest.")
    _verify_attachments(root, report_id, report, metadata, result, derived_archive)
    result.checked_reports += 1


def _verify_attachments(
    root: Path,
    report_id: str,
    report: dict[str, Any],
    metadata: dict[str, Any],
    result: VerificationResult,
    derived_archive: dict[str, dict[str, Any]],
) -> None:
    manifest_items = report.get("attachments")
    metadata_items = metadata.get("attachments")
    if not isinstance(manifest_items, list) or not isinstance(metadata_items, list):
        result.add_error(f"Report {report_id} attachment metadata is malformed.")
        return
    manifest_normalized = sorted(
        _attachment_tuple(item) for item in manifest_items if isinstance(item, dict)
    )
    metadata_normalized = sorted(
        _attachment_tuple(item) for item in metadata_items if isinstance(item, dict)
    )
    if manifest_normalized != metadata_normalized:
        result.add_error(f"Report {report_id} manifest and metadata attachment records disagree.")
    for attachment in manifest_items:
        if not isinstance(attachment, dict) or attachment.get("status") != "downloaded":
            continue
        relative = attachment.get("path")
        if not isinstance(relative, str) or not relative:
            result.add_error(f"Attachment {attachment.get('id')} has no local path.")
            continue
        record = {"sha256": attachment.get("sha256"), "size": attachment.get("size")}
        derived_archive[relative] = record
        _verify_file_record(root, relative, record, result)
        result.checked_attachments += 1


def _attachment_tuple(item: dict[str, Any]) -> tuple[str, str, str, str, str, str]:
    error = item.get("error") or item.get("skip_reason")
    return (
        str(item.get("id")),
        str(item.get("path")),
        str(item.get("sha256")),
        str(item.get("size")),
        str(item.get("status")),
        str(error),
    )


def _verify_file_record(
    root: Path, relative: str, record: dict[str, Any], result: VerificationResult
) -> None:
    try:
        path = ensure_within(root / relative, root)
        info = _require_regular(path, root)
    except (OSError, ValueError, UnsafeAttachmentPathError) as exc:
        result.add_error(f"Tracked file {relative} is missing or unsafe: {exc}")
        return
    if info.st_size != record.get("size"):
        result.add_error(f"Tracked file {relative} size mismatch.")
    if not record.get("sha256") or file_sha256(path) != record.get("sha256"):
        result.add_error(f"Tracked file {relative} SHA-256 mismatch.")


def _verify_report_directories(root: Path, declared: set[str], result: VerificationResult) -> None:
    reports_root = root / "reports"
    actual: set[str] = set()
    if reports_root.exists():
        for child in reports_root.iterdir():
            try:
                _reject_link_or_reparse(child)
            except OSError as exc:
                result.add_error(f"Unsafe report directory entry {child.name}: {exc}")
                continue
            if child.is_dir():
                actual.add(child.relative_to(root).as_posix())
    if actual != declared:
        result.add_error(
            f"Report directory set mismatch; missing={sorted(declared - actual)}, "
            f"unexpected={sorted(actual - declared)}."
        )


def _verify_database(
    root: Path, program: str, manifest_ids: set[str], result: VerificationResult
) -> None:
    db_path = root / "state.sqlite3"
    try:
        _require_regular(db_path, root)
        with StateDatabase(db_path, initialize=False) as database:
            if not database.integrity_check():
                result.add_error("SQLite integrity check failed.")
            database_ids = {
                str(item["report_id"]) for item in database.reports_for_program(program)
            }
            if database_ids != manifest_ids:
                result.add_error("Database report records do not correspond to the manifest.")
    except Exception as exc:
        result.add_error(f"Synchronization database could not be verified: {exc}")


def _verify_no_untracked_files(root: Path, allowed: set[str], result: VerificationResult) -> None:
    actual: set[str] = set()
    for current, directories, files in os.walk(root, followlinks=False):
        parent = Path(current)
        for name in [*directories, *files]:
            path = parent / name
            try:
                _reject_link_or_reparse(path)
            except OSError as exc:
                result.add_error(f"Unsafe symlink or reparse point {path.relative_to(root)}: {exc}")
        for name in files:
            actual.add((parent / name).relative_to(root).as_posix())
    unexpected = sorted(actual - allowed)
    missing = sorted(allowed - actual)
    if unexpected:
        result.add_error(f"Backup contains untracked files: {unexpected}.")
    if missing:
        result.add_error(f"Backup is missing tracked files: {missing}.")


def _scan_generated_text(
    root: Path,
    archive_files: dict[str, dict[str, Any]],
    configured_token: str | None,
    result: VerificationResult,
) -> None:
    for relative in archive_files:
        path = root / relative
        if path.name in EVIDENCE_FILES or path.suffix.lower() not in {".json", ".md"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if AUTHORIZATION_RE.search(text):
            result.add_error(f"Unredacted Authorization header found in {relative}.")
        if TEMPORARY_URL_RE.search(text):
            result.add_error(f"Temporary signed URL found in {relative}.")
        if configured_token and configured_token in text:
            result.add_error(f"Configured API token found in generated file {relative}.")


def _document_data(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("data"), dict):
        return None
    data: dict[str, Any] = value["data"]
    return data


def _require_regular(path: Path, root: Path) -> os.stat_result:
    ensure_within(path, root)
    info = path.lstat()
    _reject_info(info)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("path is not a regular file")
    return info


def _reject_link_or_reparse(path: Path) -> None:
    _reject_info(path.lstat())


def _reject_info(info: os.stat_result) -> None:
    if stat.S_ISLNK(info.st_mode):
        raise OSError("symbolic links are forbidden")
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if attributes & reparse:
        raise OSError("filesystem reparse points are forbidden")


def _inspect_value(value: Any, location: str, result: VerificationResult, *, secrets: bool) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if (
                normalized in {"expiring_url", "presigned_url", "pre_signed_url"}
                and item != REDACTED_URL
            ):
                result.add_error(f"Unredacted temporary URL field found in {location}.")
            if (
                secrets
                and normalized
                in {
                    "authorization",
                    "cookie",
                    "cookies",
                    "token",
                    "api_token",
                    "password",
                }
                and item not in {"<redacted>", None}
            ):
                result.add_error(f"Sensitive field {key!r} is not redacted in {location}.")
            _inspect_value(item, location, result, secrets=secrets)
    elif isinstance(value, list):
        for item in value:
            _inspect_value(item, location, result, secrets=secrets)
