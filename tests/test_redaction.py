from __future__ import annotations

from h1vault.security.redaction import REDACTED_SECRET, REDACTED_URL, redact_data, redact_text


def test_recursive_redaction() -> None:
    value = {
        "expiring_url": "https://x/?signature=secret",
        "Authorization": "Basic abc",
        "nested": [{"token": "secret"}, "https://x/?sig=secret"],
        "safe": "value",
    }
    result = redact_data(value)
    assert result["expiring_url"] == REDACTED_URL
    assert result["Authorization"] == REDACTED_SECRET
    assert result["nested"][0]["token"] == REDACTED_SECRET
    assert "secret" not in result["nested"][1]
    assert result["safe"] == "value"


def test_authorization_and_explicit_secret_text_redaction() -> None:
    text = redact_text("Authorization: Basic abc value TOKEN", ["TOKEN"])
    assert "abc" not in text and "TOKEN" not in text
