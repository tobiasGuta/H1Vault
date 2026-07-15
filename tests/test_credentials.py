from __future__ import annotations

import logging

import pytest
from typer.testing import CliRunner

from h1vault.cli import app
from h1vault.credentials import clear_credentials, resolve_credentials
from h1vault.exceptions import AuthenticationError
from h1vault.logging_config import RedactionFilter


def test_environment_credentials_override_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H1_API_USERNAME", "env-user")
    monkeypatch.setenv("H1_API_TOKEN", "env-secret")
    monkeypatch.setattr("keyring.get_password", lambda *_: "stored")
    creds = resolve_credentials()
    assert (creds.username, creds.token, creds.source) == (
        "env-user",
        "env-secret",
        "environment",
    )


@pytest.mark.parametrize(
    ("username", "token"), [(None, None), ("only-user", None), (None, "only-token")]
)
def test_missing_or_partial_credentials_are_actionable(
    monkeypatch: pytest.MonkeyPatch, username: str | None, token: str | None
) -> None:
    monkeypatch.delenv("H1_API_USERNAME", raising=False)
    monkeypatch.delenv("H1_API_TOKEN", raising=False)
    if username:
        monkeypatch.setenv("H1_API_USERNAME", username)
    if token:
        monkeypatch.setenv("H1_API_TOKEN", token)
    monkeypatch.setattr("keyring.get_password", lambda *_: None)
    with pytest.raises(AuthenticationError, match=r"both|No HackerOne"):
        resolve_credentials()


def test_clear_removes_only_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H1_API_TOKEN", "still-here")
    deleted: list[str] = []
    monkeypatch.setattr("keyring.get_password", lambda _service, name: f"value-{name}")
    monkeypatch.setattr("keyring.delete_password", lambda _service, name: deleted.append(name))
    clear_credentials()
    assert len(deleted) == 2
    assert __import__("os").environ["H1_API_TOKEN"] == "still-here"


def test_redaction_filter_removes_environment_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H1_API_TOKEN", "super-secret")
    record = logging.LogRecord("test", logging.INFO, "", 0, "value super-secret", (), None)
    assert RedactionFilter().filter(record)
    assert "super-secret" not in record.getMessage()


def test_auth_status_never_prints_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H1_API_USERNAME", "identifier")
    monkeypatch.setenv("H1_API_TOKEN", "never-print-this")
    result = CliRunner().invoke(app, ["auth", "status"])
    assert result.exit_code == 0
    assert "never-print-this" not in result.stdout
    assert "environment" in result.stdout


def test_partial_environment_status_reports_each_component(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("H1_API_USERNAME", "identifier")
    monkeypatch.delenv("H1_API_TOKEN", raising=False)
    result = CliRunner().invoke(app, ["auth", "status"])
    assert result.exit_code == 0
    assert "identifier configured: yes" in result.stdout
    assert "Token available: no" in result.stdout
