"""Atomic normalized JSON and Markdown report export."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from h1vault import __version__
from h1vault.backup.io import atomic_write, fingerprint, write_json
from h1vault.backup.renderer import extract_activities, render_original, render_report
from h1vault.security.filenames import report_directory_name, safe_filename
from h1vault.security.redaction import redact_data, redact_temporary_capabilities


@dataclass(frozen=True)
class ExportResult:
    directory: Path
    report_fingerprint: str
    files: tuple[str, ...]


def choose_report_directory(reports_root: Path, report_id: str, title: str) -> Path:
    """Retain ID identity and safely rename only the cosmetic title suffix."""
    target = reports_root / report_directory_name(report_id, title)
    safe_id = safe_filename(report_id, fallback="report", max_length=40)
    existing = (
        sorted(
            child
            for child in reports_root.iterdir()
            if child.is_dir() and child.name.startswith(f"{safe_id}-")
        )
        if reports_root.exists()
        else []
    )
    if target.exists():
        return target
    if existing:
        existing[0].rename(target)
        return target
    return target


def export_report(
    report: dict[str, Any],
    reports_root: Path,
    *,
    program: str,
    synchronized_at: str,
    attachment_records: list[dict[str, Any]],
    warnings: list[str] | None = None,
) -> ExportResult:
    """Write evidence-preserving raw/original and clearly sanitized representations."""
    report_id = str(report["id"])
    raw_attributes = report.get("attributes")
    attributes: dict[str, Any] = raw_attributes if isinstance(raw_attributes, dict) else {}
    title = str(attributes.get("title") or "untitled")
    directory = choose_report_directory(reports_root, report_id, title)
    directory.mkdir(parents=True, exist_ok=True)
    raw_report = redact_temporary_capabilities(report)
    safe_report = redact_data(report)
    timeline = redact_data(extract_activities(report))
    report_hash = fingerprint(raw_report)
    paths = (
        "report.raw.json",
        "report.sanitized.json",
        "report.md",
        "original-report.md",
        "timeline.json",
        "metadata.json",
    )
    write_json(directory / "report.raw.json", {"data": raw_report})
    write_json(directory / "report.sanitized.json", {"data": safe_report})
    write_json(directory / "timeline.json", {"schema_version": 1, "activities": timeline})
    atomic_write(
        directory / "report.md",
        render_report(
            safe_report, synchronized_at=synchronized_at, attachment_records=attachment_records
        ).encode("utf-8"),
    )
    atomic_write(directory / "original-report.md", render_original(report).encode("utf-8"))
    metadata = {
        "schema_version": 2,
        "h1vault_version": __version__,
        "source_api_version": "v1",
        "report_id": report_id,
        "program_handle": program,
        "synchronized_at": synchronized_at,
        "report_response_sha256": report_hash,
        "exported_file_paths": list(paths),
        "attachments": redact_data(attachment_records),
        "attachments_skipped": any(item.get("skip_reason") for item in attachment_records),
        "skip_reasons": [
            item["skip_reason"] for item in attachment_records if item.get("skip_reason")
        ],
        "errors": [],
        "warnings": warnings or [],
    }
    write_json(directory / "metadata.json", metadata)
    (directory / "report.json").unlink(missing_ok=True)
    return ExportResult(directory, report_hash, paths)


def remove_empty_old_directory(path: Path) -> None:
    if path.exists() and not any(path.iterdir()):
        shutil.rmtree(path)
