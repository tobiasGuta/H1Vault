from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from h1vault.cli import app

runner = CliRunner()


def test_help_and_version() -> None:
    help_result = runner.invoke(app, ["--help"])
    version_result = runner.invoke(app, ["--version"])
    assert help_result.exit_code == 0
    assert "Read-only" in help_result.stdout
    assert version_result.exit_code == 0
    assert "H1Vault 0.1.0" in version_result.stdout


def test_python_module_entrypoint_help() -> None:
    result = runner.invoke(app, ["report", "--help"])
    assert result.exit_code == 0
    assert "Export one report" in result.stdout


@pytest.mark.parametrize(
    "arguments", [["sync"], ["verify"], ["snapshot"], ["report", "export", "123"]]
)
def test_missing_required_options(arguments: list[str]) -> None:
    result = runner.invoke(app, arguments)
    assert result.exit_code == 2


def test_programs_json_is_machine_readable(monkeypatch: pytest.MonkeyPatch, report_factory) -> None:
    monkeypatch.setattr("h1vault.cli._all_reports", lambda: [report_factory()])
    result = runner.invoke(app, ["programs", "list", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["programs"][0]["program_handle"] == "example-program"


def test_reports_json_filters_locally(monkeypatch: pytest.MonkeyPatch, report_factory) -> None:
    monkeypatch.setattr(
        "h1vault.cli._all_reports",
        lambda: [report_factory("1", state="triaged"), report_factory("2", state="resolved")],
    )
    result = runner.invoke(app, ["reports", "list", "--state", "resolved", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert [item["report_id"] for item in parsed["reports"]] == ["2"]


def test_keyboard_interrupt_has_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr("h1vault.cli._all_reports", interrupt)
    result = runner.invoke(app, ["programs", "list"])
    assert result.exit_code != 0
