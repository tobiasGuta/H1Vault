"""Cross-platform safe names and containment checks."""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path

from h1vault.exceptions import UnsafeAttachmentPathError

WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
UNSAFE_RE = re.compile(r"[<>:\"/\\|?*\x00-\x1f]")
SPACE_RE = re.compile(r"\s+")


def safe_filename(name: str, *, fallback: str = "unnamed", max_length: int = 120) -> str:
    """Convert an untrusted leaf filename into a deterministic safe leaf name."""
    normalized = unicodedata.normalize("NFKC", name)
    normalized = UNSAFE_RE.sub("_", normalized)
    normalized = SPACE_RE.sub(" ", normalized).strip(" .")
    if not normalized or normalized in {".", ".."}:
        normalized = fallback
    stem, dot, suffix = normalized.rpartition(".")
    base = stem if dot else normalized
    extension = f".{suffix}" if dot and suffix else ""
    if base.upper() in WINDOWS_RESERVED:
        base = f"_{base}"
    allowed_base = max(1, max_length - len(extension))
    base = base[:allowed_base].rstrip(" .") or fallback
    extension = extension[: max(0, max_length - len(base))].rstrip(" .")
    return f"{base}{extension}"


def report_directory_name(report_id: str, title: str) -> str:
    safe_id = safe_filename(report_id, fallback="report", max_length=40)
    slug = safe_filename(title.casefold(), fallback="untitled", max_length=75)
    slug = re.sub(r"[^a-z0-9._-]+", "-", slug).strip("-.") or "untitled"
    return f"{safe_id}-{slug}"


def attachment_filename(attachment_id: str, original: str) -> str:
    return (
        f"{safe_filename(attachment_id, fallback='attachment', max_length=40)}_"
        f"{safe_filename(original)}"
    )


def ensure_within(path: Path, root: Path) -> Path:
    """Resolve and require a destination to remain under its expected root."""
    resolved_root = root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise UnsafeAttachmentPathError(
            f"Unsafe path escapes backup directory: {path.name}"
        ) from exc
    return resolved
