"""Portable ZIP creation from an explicit, verified manifest allowlist."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path
from typing import Any

from h1vault.backup.verifier import VerificationResult, verify_backup
from h1vault.exceptions import BackupIntegrityError
from h1vault.security.filenames import ensure_within, safe_filename

CHUNK_SIZE = 1024 * 1024


def create_snapshot(
    output: Path,
    program: str,
    destination: Path,
    *,
    force: bool = False,
    configured_token: str | None = None,
) -> tuple[Path, VerificationResult]:
    result = verify_backup(output, program, configured_token=configured_token)
    structural_markers = (
        "untracked files",
        "symlink",
        "reparse point",
        "report directory set mismatch",
        "unsafe path",
    )
    if any(marker in error.casefold() for error in result.errors for marker in structural_markers):
        raise BackupIntegrityError(
            "Snapshot refused because the backup contains untracked or unsafe filesystem entries."
        )
    if not result.valid and not force:
        raise BackupIntegrityError(
            "Backup verification failed; refusing to create a portable snapshot without --force."
        )
    if result.manifest_sha256 is None or not result.archive_files:
        raise BackupIntegrityError("A readable schema-2 manifest is required for snapshots.")
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
    archive_root = Path(safe_filename(program, fallback="program"))
    records: dict[str, dict[str, Any]] = {
        "manifest.json": {
            "sha256": result.manifest_sha256,
            "size": (root / "manifest.json").lstat().st_size,
        },
        **result.archive_files,
    }
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
        ) as archive:
            for relative in ["manifest.json", *sorted(result.archive_files)]:
                _archive_regular_file(
                    archive,
                    root,
                    relative,
                    records[relative],
                    archive_root / relative,
                    allow_mismatch=force,
                )
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination, result


def _archive_regular_file(
    archive: zipfile.ZipFile,
    root: Path,
    relative: str,
    expected: dict[str, Any],
    archive_name: Path,
    *,
    allow_mismatch: bool,
) -> None:
    path = ensure_within(root / relative, root)
    before = path.lstat()
    _reject_non_regular(before, relative)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _reject_non_regular(opened, relative)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise BackupIntegrityError(f"Tracked file changed while opening: {relative}")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
        if not allow_mismatch and (
            digest.hexdigest() != expected.get("sha256") or size != expected.get("size")
        ):
            raise BackupIntegrityError(f"Tracked file changed before snapshot: {relative}")
        os.lseek(descriptor, 0, os.SEEK_SET)
        with archive.open(archive_name.as_posix(), "w", force_zip64=True) as target:
            while chunk := os.read(descriptor, CHUNK_SIZE):
                target.write(chunk)
    finally:
        os.close(descriptor)


def _reject_non_regular(info: os.stat_result, relative: str) -> None:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(info.st_mode) or attributes & reparse or not stat.S_ISREG(info.st_mode):
        raise BackupIntegrityError(f"Snapshot source is not a regular file: {relative}")
