"""Integrity and confidentiality verification for local backups."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from h1vault.backup.io import file_sha256
from h1vault.backup.manifest import StateDatabase
from h1vault.security.filenames import ensure_within, safe_filename
from h1vault.security.redaction import REDACTED_URL

AUTHORIZATION_RE = re.compile(r"(?i)authorization\s*[:=]\s*(?:basic|bearer)\s+(?!<redacted>)\S+")
TEMPORARY_URL_RE = re.compile(
    r"https://[^\s\"']+[?&](?:x-amz-|signature=|sig=|credential=|token=)", re.IGNORECASE
)


@dataclass
class VerificationResult:
    program: str
    backup: str
    valid: bool = True
    checked_reports: int = 0
    checked_attachments: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

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
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        result.add_error(f"Manifest is missing or invalid JSON: {exc}")
        return result
    if manifest.get("program_handle") != program:
        result.add_error("Manifest program handle does not match the requested program.")
    temporary_files = list(root.rglob("*.part")) + list(root.rglob(".*.part"))
    if temporary_files:
        result.add_error(f"Found {len(set(temporary_files))} incomplete .part file(s).")
    manifest_ids: set[str] = set()
    for report in manifest.get("reports", []):
        if not isinstance(report, dict):
            result.add_error("Manifest contains a malformed report record.")
            continue
        report_id = str(report.get("id"))
        manifest_ids.add(report_id)
        try:
            report_dir = ensure_within(root / str(report["path"]), root)
        except Exception as exc:
            result.add_error(f"Report {report_id} has an unsafe path: {exc}")
            continue
        for filename in (
            "report.md",
            "report.json",
            "original-report.md",
            "timeline.json",
            "metadata.json",
        ):
            if not (report_dir / filename).is_file():
                result.add_error(f"Report {report_id} is missing {filename}.")
        for filename in ("report.json", "timeline.json", "metadata.json"):
            path = report_dir / filename
            if path.is_file():
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    _inspect_value(value, f"report {report_id}/{filename}", result)
                except (OSError, ValueError) as exc:
                    result.add_error(f"Report {report_id} has invalid {filename}: {exc}")
        result.checked_reports += 1
        for attachment in report.get("attachments", []):
            if not isinstance(attachment, dict) or attachment.get("status") != "downloaded":
                continue
            relative = attachment.get("path")
            if not relative:
                result.add_error(f"Attachment {attachment.get('id')} has no local path.")
                continue
            try:
                path = ensure_within(root / str(relative), root)
            except Exception as exc:
                result.add_error(f"Attachment {attachment.get('id')} escapes the backup: {exc}")
                continue
            if path.is_symlink():
                result.add_error(f"Attachment {attachment.get('id')} is a symlink.")
            elif not path.is_file():
                result.add_error(f"Attachment {attachment.get('id')} is missing.")
            elif not attachment.get("sha256") or file_sha256(path) != attachment["sha256"]:
                result.add_error(f"Attachment {attachment.get('id')} SHA-256 mismatch.")
            result.checked_attachments += 1
    db_path = root / "state.sqlite3"
    if not db_path.is_file():
        result.add_error("Synchronization database is missing.")
    else:
        try:
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
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".json", ".md", ".log"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if AUTHORIZATION_RE.search(text):
            result.add_error(f"Unredacted Authorization header found in {path.relative_to(root)}.")
        if TEMPORARY_URL_RE.search(text):
            result.add_error(f"Temporary signed URL found in {path.relative_to(root)}.")
        if configured_token and configured_token in text:
            result.add_error(f"Configured API token found in {path.relative_to(root)}.")
    return result


def _inspect_value(value: Any, location: str, result: VerificationResult) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if (
                normalized in {"expiring_url", "presigned_url", "pre_signed_url"}
                and item != REDACTED_URL
            ):
                result.add_error(f"Unredacted temporary URL field found in {location}.")
            if normalized in {
                "authorization",
                "cookie",
                "cookies",
                "token",
                "api_token",
                "password",
            } and item not in {"<redacted>", None}:
                result.add_error(f"Sensitive field {key!r} is not redacted in {location}.")
            _inspect_value(item, location, result)
    elif isinstance(value, list):
        for item in value:
            _inspect_value(item, location, result)
