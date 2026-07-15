"""Recursive secret and temporary-capability redaction."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED_URL = "<redacted-temporary-download-url>"
REDACTED_SECRET = "<redacted>"  # noqa: S105 - public redaction marker
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "set-cookie",
    "token",
    "api_token",
    "access_token",
    "password",
}
TEMPORARY_KEYS = {"expiring_url", "presigned_url", "pre_signed_url"}
URL_SECRET_RE = re.compile(r"(?i)([?&](?:signature|sig|token|key|credential|x-amz-[^=]+)=)[^&\s]+")
AUTH_RE = re.compile(r"(?i)(authorization\s*[:=]\s*)(?:basic|bearer)\s+[^\s,;]+")


def redact_data(value: Any) -> Any:
    """Return a JSON-compatible copy with secret-bearing fields redacted."""
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in TEMPORARY_KEYS:
                result[str(key)] = REDACTED_URL
            elif normalized in {item.replace("-", "_") for item in SENSITIVE_KEYS}:
                result[str(key)] = REDACTED_SECRET
            else:
                result[str(key)] = redact_data(item)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str, secrets: Sequence[str] = ()) -> str:
    result = AUTH_RE.sub(r"\1<redacted>", text)
    result = URL_SECRET_RE.sub(r"\1<redacted>", result)
    for secret in secrets:
        if secret:
            result = result.replace(secret, REDACTED_SECRET)
    return result
