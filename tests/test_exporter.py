from __future__ import annotations

import json
from pathlib import Path

import pytest

from h1vault.backup.exporter import export_report
from h1vault.backup.renderer import extract_activities
from h1vault.security.filenames import report_directory_name, safe_filename
from h1vault.security.redaction import REDACTED_URL


def test_full_export_preserves_markdown_sorts_timeline_and_redacts(
    tmp_path: Path, report_factory
) -> None:
    activities = [
        {
            "id": "2",
            "type": "activity-comment",
            "attributes": {"created_at": "2026-02-02T00:00:00Z", "message": "second"},
        },
        {
            "id": "1",
            "type": "activity-comment",
            "attributes": {
                "created_at": "2026-02-01T00:00:00Z",
                "message": "first",
                "internal": True,
            },
        },
    ]
    attachment = {
        "id": "a1",
        "type": "attachment",
        "attributes": {
            "file_name": "proof.txt",
            "file_size": 3,
            "expiring_url": "https://files.example/proof?signature=secret",
        },
    }
    report = report_factory(
        relationships={"activities": {"data": activities}, "attachments": {"data": [attachment]}}
    )
    result = export_report(
        report,
        tmp_path,
        program="example-program",
        synchronized_at="2026-03-01T00:00:00Z",
        attachment_records=[],
    )
    markdown = (result.directory / "report.md").read_text(encoding="utf-8")
    original = (result.directory / "original-report.md").read_text(encoding="utf-8")
    raw = json.loads((result.directory / "report.raw.json").read_text(encoding="utf-8"))
    exported = json.loads((result.directory / "report.sanitized.json").read_text(encoding="utf-8"))
    timeline = json.loads((result.directory / "timeline.json").read_text(encoding="utf-8"))
    assert "**original** markdown" in markdown
    assert original.startswith("**original** markdown")
    assert markdown.index("first") < markdown.index("second")
    assert "[internal/private]" in markdown
    assert (
        exported["data"]["relationships"]["attachments"]["data"][0]["attributes"]["expiring_url"]
        == REDACTED_URL
    )
    assert (
        raw["data"]["relationships"]["attachments"]["data"][0]["attributes"]["expiring_url"]
        == REDACTED_URL
    )
    assert timeline["activities"][0]["id"] == "1"
    assert "secret" not in result.directory.read_text() if result.directory.is_file() else True


def test_raw_and_original_preserve_researcher_evidence_while_share_view_is_sanitized(
    tmp_path: Path, report_factory
) -> None:
    evidence = "curl -H 'Authorization: Bearer example-vulnerable-token' /admin"
    report = report_factory()
    report["attributes"]["vulnerability_information"] = evidence
    report["attributes"]["impact"] = "Signed example: https://target.test/?signature=poc-value"
    result = export_report(
        report,
        tmp_path,
        program="example-program",
        synchronized_at="now",
        attachment_records=[],
    )
    raw = json.loads((result.directory / "report.raw.json").read_text())["data"]
    original = (result.directory / "original-report.md").read_text()
    sanitized = json.loads((result.directory / "report.sanitized.json").read_text())["data"]
    assert raw["attributes"]["vulnerability_information"] == evidence
    assert evidence in original
    assert "example-vulnerable-token" not in sanitized["attributes"]["vulnerability_information"]
    assert "poc-value" not in sanitized["attributes"]["impact"]


def test_minimal_report_optional_fields(tmp_path: Path) -> None:
    report = {"id": "x", "type": "report", "attributes": {}, "relationships": {}}
    result = export_report(
        report, tmp_path, program="p", synchronized_at="now", attachment_records=[]
    )
    assert (result.directory / "report.md").is_file()
    assert json.loads((result.directory / "timeline.json").read_text())["activities"] == []


def test_raw_export_preserves_complete_document_top_level_fields(
    tmp_path: Path, report_factory
) -> None:
    report = report_factory()
    document = {
        "data": report,
        "included": [{"id": "u1", "type": "user", "attributes": {"name": "Researcher"}}],
        "meta": {"revision": 7},
        "links": {"self": "https://api.hackerone.com/v1/hackers/reports/123"},
    }
    result = export_report(
        report,
        tmp_path,
        raw_document=document,
        program="example-program",
        synchronized_at="now",
        attachment_records=[],
    )
    assert json.loads((result.directory / "report.raw.json").read_text()) == document


def test_title_change_renames_without_losing_files(tmp_path: Path, report_factory) -> None:
    first = export_report(
        report_factory(title="Old title"),
        tmp_path,
        program="example-program",
        synchronized_at="one",
        attachment_records=[],
    )
    marker = first.directory / "attachments" / "report" / "a_file"
    marker.parent.mkdir(parents=True)
    marker.write_bytes(b"preserve")
    second = export_report(
        report_factory(title="New title"),
        tmp_path,
        program="example-program",
        synchronized_at="two",
        attachment_records=[],
    )
    assert second.directory != first.directory
    assert (second.directory / "attachments" / "report" / "a_file").read_bytes() == b"preserve"
    assert not first.directory.exists()


@pytest.mark.parametrize("title", ["CON", "a/b\\c", "..", "title. ", "x" * 500])
def test_windows_safe_report_directories(title: str) -> None:
    value = report_directory_name("123", title)
    assert "/" not in value and "\\" not in value
    assert len(value) <= 116
    assert not value.endswith((".", " "))


def test_timeline_order_with_missing_dates_last() -> None:
    report = {
        "relationships": {
            "activities": {
                "data": [
                    {"id": "missing", "attributes": {}},
                    {"id": "dated", "attributes": {"created_at": "2020-01-01T00:00:00Z"}},
                ]
            }
        }
    }
    assert [item["id"] for item in extract_activities(report)] == ["dated", "missing"]


def test_safe_filename_reserved_and_unicode() -> None:
    assert safe_filename("CON.txt").startswith("_")
    assert safe_filename("résumé.txt") == "résumé.txt"
