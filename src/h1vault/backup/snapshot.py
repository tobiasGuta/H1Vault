"""Portable ZIP creation only from a verified backup."""

from __future__ import annotations

import zipfile
from pathlib import Path

from h1vault.backup.verifier import VerificationResult, verify_backup
from h1vault.exceptions import BackupIntegrityError
from h1vault.security.filenames import safe_filename


def create_snapshot(
    output: Path,
    program: str,
    destination: Path,
    *,
    force: bool = False,
    configured_token: str | None = None,
) -> tuple[Path, VerificationResult]:
    result = verify_backup(output, program, configured_token=configured_token)
    if not result.valid and not force:
        raise BackupIntegrityError(
            "Backup verification failed; refusing to create a portable snapshot without --force."
        )
    root = output / safe_filename(program, fallback="program")
    destination = destination.resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError:
        pass
    else:
        raise BackupIntegrityError(
            "Snapshot destination must be outside the source backup directory."
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
        ) as archive:
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(root)
                if path.name == "state.sqlite3" or path.suffix in {".part", ".log"}:
                    continue
                if path.name.startswith(".") and path.name.endswith(".tmp"):
                    continue
                archive.write(path, Path(safe_filename(program, fallback="program")) / relative)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination, result
