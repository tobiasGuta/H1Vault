"""Typer command-line interface for H1Vault."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import keyring
import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from h1vault import __version__
from h1vault.api.client import HackerOneClient
from h1vault.api.models import filter_program, program_handle
from h1vault.backup.exporter import export_report
from h1vault.backup.renderer import (
    attributes_of,
    bounty_total,
    extract_attachments,
    relationship_label,
)
from h1vault.backup.snapshot import create_snapshot
from h1vault.backup.synchronizer import Synchronizer, SyncOptions
from h1vault.backup.verifier import verify_backup
from h1vault.config import Settings, load_settings
from h1vault.credentials import (
    CredentialStatus,
    clear_credentials,
    credential_status,
    resolve_credentials,
    store_credentials,
)
from h1vault.exceptions import AttachmentDownloadError, ExpiredAttachmentURLError, H1VaultError
from h1vault.logging_config import configure_logging
from h1vault.security.downloads import AttachmentDownloader
from h1vault.security.filenames import attachment_filename, safe_filename

console = Console(stderr=False)
error_console = Console(stderr=True)
app = typer.Typer(
    name="h1vault",
    help="Read-only local backups of your own HackerOne reports.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
auth_app = typer.Typer(help="Manage OS-keyring credentials.", no_args_is_help=True)
programs_app = typer.Typer(
    help="Inspect programs represented in your own report history.", no_args_is_help=True
)
reports_app = typer.Typer(help="List your accessible HackerOne reports.", no_args_is_help=True)
report_app = typer.Typer(help="Export one report accessible to your account.", no_args_is_help=True)
app.add_typer(auth_app, name="auth")
app.add_typer(programs_app, name="programs")
app.add_typer(reports_app, name="reports")
app.add_typer(report_app, name="report")


class Runtime:
    settings: Settings
    debug: bool


runtime = Runtime()


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"H1Vault {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable DEBUG logging.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Show errors only.")] = False,
    log_file: Annotated[
        Path | None, typer.Option("--log-file", help="Write redacted JSON logs.")
    ] = None,
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """Configure H1Vault without accepting credentials as arguments."""
    del version
    try:
        runtime.settings = load_settings()
    except H1VaultError as exc:
        error_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(2) from exc
    level = "DEBUG" if verbose else "ERROR" if quiet else runtime.settings.logging.level
    runtime.debug = verbose
    configure_logging(level, log_file)


@auth_app.command("set")
def auth_set() -> None:
    """Securely save a token pair in the operating-system keyring."""
    username = typer.prompt("API-token identifier")
    token = typer.prompt("API-token value", hide_input=True, confirmation_prompt=True)
    _guard(
        lambda: store_credentials(username, token), success="Credentials stored in the OS keyring."
    )


@auth_app.command("status")
def auth_status() -> None:
    """Show availability and active source, never token content."""
    try:
        status = credential_status()
        _print_status(status)
    except H1VaultError as exc:
        _fail(exc)


@auth_app.command("clear")
def auth_clear(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Remove stored keyring values; environment variables are unchanged."""
    if not yes and not typer.confirm("Remove H1Vault credentials from the OS keyring?"):
        raise typer.Abort()
    _guard(
        clear_credentials,
        success="Stored keyring credentials cleared. Environment variables were not changed.",
    )


@app.command()
def doctor(
    output: Annotated[Path | None, typer.Option("--output", help="Directory to test.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON only.")] = False,
) -> None:
    """Check local prerequisites and one minimal authenticated API request."""
    target = output or runtime.settings.backup.default_output
    checks: list[dict[str, Any]] = []
    checks.append(
        {
            "name": "python_version",
            "ok": sys.version_info >= (3, 12),
            "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        }
    )
    try:
        target.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=target, prefix=".h1vault-doctor-", delete=True):
            pass
        checks.append({"name": "output_writable", "ok": True, "detail": str(target)})
    except OSError as exc:
        checks.append({"name": "output_writable", "ok": False, "detail": str(exc)})
    backend = keyring.get_keyring()
    priority = getattr(backend, "priority", 0)
    checks.append(
        {"name": "keyring_available", "ok": bool(priority), "detail": type(backend).__name__}
    )
    credentials = None
    try:
        credentials = resolve_credentials()
        checks.append({"name": "credentials_available", "ok": True, "detail": credentials.source})
    except H1VaultError as exc:
        checks.append({"name": "credentials_available", "ok": False, "detail": str(exc)})
    try:
        connection = sqlite3.connect(":memory:")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        connection.close()
        checks.append({"name": "database_integrity", "ok": integrity == "ok", "detail": integrity})
    except sqlite3.Error as exc:
        checks.append({"name": "database_integrity", "ok": False, "detail": str(exc)})
    if credentials:
        try:
            with HackerOneClient(
                credentials,
                max_retries=runtime.settings.api.max_retries,
                concurrency=runtime.settings.api.concurrency,
            ) as client:
                client.doctor_request()
            checks.extend(
                [
                    {"name": "api_connectivity", "ok": True, "detail": "reachable"},
                    {"name": "authentication_valid", "ok": True, "detail": "accepted"},
                ]
            )
        except H1VaultError as exc:
            checks.extend(
                [
                    {"name": "api_connectivity", "ok": False, "detail": str(exc)},
                    {"name": "authentication_valid", "ok": False, "detail": str(exc)},
                ]
            )
    ok = all(check["ok"] for check in checks)
    if json_output:
        typer.echo(json.dumps({"ok": ok, "checks": checks}, sort_keys=True))
    else:
        table = Table(title=f"H1Vault {__version__} doctor")
        table.add_column("Check")
        table.add_column("Result")
        table.add_column("Detail")
        for check in checks:
            table.add_row(check["name"], "OK" if check["ok"] else "FAIL", str(check["detail"]))
        console.print(table)
    if not ok:
        raise typer.Exit(1)


@programs_app.command("list")
def programs_list(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON only.")] = False,
) -> None:
    """List programs represented in this researcher's owned report history."""
    try:
        reports = _all_reports()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for report in reports:
            handle = program_handle(report)
            if handle:
                grouped.setdefault(handle, []).append(report)
        result = []
        for handle, items in sorted(grouped.items(), key=lambda pair: pair[0].casefold()):
            dates = [
                str(
                    attributes_of(item).get("submitted_at") or attributes_of(item).get("created_at")
                )
                for item in items
                if attributes_of(item).get("submitted_at") or attributes_of(item).get("created_at")
            ]
            result.append(
                {
                    "program_handle": handle,
                    "report_count": len(items),
                    "earliest_report_date": min(dates) if dates else None,
                    "latest_report_date": max(dates) if dates else None,
                }
            )
        if json_output:
            typer.echo(json.dumps({"programs": result}, ensure_ascii=False, sort_keys=True))
            return
        table = Table(title="Programs represented in your own report history")
        for heading in ("Program handle", "Reports", "Earliest", "Latest"):
            table.add_column(heading)
        for item in result:
            table.add_row(
                str(item["program_handle"]),
                str(item["report_count"]),
                str(item["earliest_report_date"] or ""),
                str(item["latest_report_date"] or ""),
            )
        console.print(table)
    except H1VaultError as exc:
        _fail(exc)


@reports_app.command("list")
def reports_list(
    program: Annotated[str | None, typer.Option("--program")] = None,
    state: Annotated[str | None, typer.Option("--state")] = None,
    severity: Annotated[str | None, typer.Option("--severity")] = None,
    limit: Annotated[int | None, typer.Option("--limit", min=1)] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List reports with local optional-field-tolerant filtering."""
    try:
        reports = _all_reports()
        if program:
            reports = filter_program(reports, program)
        rows = [_report_row(item) for item in reports]
        if state:
            rows = [
                item
                for item in rows
                if item["state"] and item["state"].casefold() == state.casefold()
            ]
        if severity:
            rows = [
                item
                for item in rows
                if item["severity"] and item["severity"].casefold() == severity.casefold()
            ]
        if limit is not None:
            rows = rows[:limit]
        if json_output:
            typer.echo(json.dumps({"reports": rows}, ensure_ascii=False, sort_keys=True))
            return
        table = Table(title="Reports accessible to this account")
        for heading in (
            "ID",
            "Program",
            "Title",
            "State",
            "Severity",
            "Created",
            "Last activity",
            "Bounty",
        ):
            table.add_column(heading)
        for row in rows:
            table.add_row(*(str(row[key] or "") for key in row))
        console.print(table)
    except H1VaultError as exc:
        _fail(exc)


@report_app.command("export")
def report_export(
    report_id: Annotated[
        str, typer.Argument(help="An exact report ID accessible to this account.")
    ],
    output: Annotated[Path, typer.Option("--output", help="Backup root directory.")],
) -> None:
    """Export exactly one accessible report; never enumerate adjacent IDs."""
    console.print("This command only works for a report accessible to the authenticated account.")
    try:
        credentials = resolve_credentials()
        with HackerOneClient(
            credentials,
            max_retries=runtime.settings.api.max_retries,
            concurrency=runtime.settings.api.concurrency,
        ) as client:
            response = client.get_report_response(report_id)
            report = response.resource
            handle = program_handle(report) or "unknown-program"
            root = output / safe_filename(handle, fallback="program")
            directory = root / "reports"
            attachments = _download_single_attachments(report, directory, root, client)
            result = export_report(
                report,
                directory,
                raw_document=response.raw_document,
                program=handle,
                synchronized_at=datetime.now(UTC).isoformat(),
                attachment_records=attachments,
            )
        console.print(f"Exported report {report_id} to {result.directory}")
    except H1VaultError as exc:
        _fail(exc)


@app.command()
def sync(
    program: Annotated[str, typer.Option("--program", help="Exact HackerOne program handle.")],
    output: Annotated[Path, typer.Option("--output", help="Backup root directory.")],
    include_attachments: Annotated[
        bool | None,
        typer.Option("--include-attachments/--skip-attachments", help="Download attachments."),
    ] = None,
    max_attachment_size_mb: Annotated[
        int | None, typer.Option("--max-attachment-size-mb", min=0)
    ] = None,
    refresh: Annotated[bool, typer.Option("--refresh")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
    fail_fast: Annotated[bool, typer.Option("--fail-fast")] = False,
) -> None:
    """Incrementally synchronize reports for one exact program handle."""
    try:
        credentials = resolve_credentials()
        options = SyncOptions(
            program,
            output,
            (
                include_attachments
                if include_attachments is not None
                else runtime.settings.backup.include_attachments
            ),
            (
                max_attachment_size_mb
                if max_attachment_size_mb is not None
                else runtime.settings.backup.max_attachment_size_mb
            ),
            refresh,
            dry_run,
            fail_fast,
        )
        with HackerOneClient(
            credentials,
            max_retries=runtime.settings.api.max_retries,
            concurrency=runtime.settings.api.concurrency,
        ) as client:
            if console.is_terminal and not json_output and not dry_run:
                progress = Progress(
                    SpinnerColumn(),
                    TextColumn("{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    console=console,
                )
                with progress:
                    reports_task = progress.add_task("Reports", total=0)
                    attachments_task = progress.add_task("Attachments", total=0)

                    def update_progress(event: str, amount: int) -> None:
                        if event == "reports_total":
                            progress.update(reports_task, total=amount)
                        elif event == "report_complete":
                            progress.advance(reports_task, amount)
                        elif event == "attachments_total":
                            current = progress.tasks[attachments_task].total or 0
                            progress.update(attachments_task, total=current + amount)
                        elif event == "attachment_complete":
                            progress.advance(attachments_task, amount)

                    summary = Synchronizer(client, options, progress=update_progress).run()
            else:
                summary = Synchronizer(client, options).run()
        if json_output:
            typer.echo(json.dumps(summary.to_dict(), ensure_ascii=False, sort_keys=True))
        else:
            _print_sync_summary(summary.to_dict())
        if summary.errors:
            raise typer.Exit(1)
    except H1VaultError as exc:
        _fail(exc, json_output=json_output)


@app.command()
def verify(
    program: Annotated[str, typer.Option("--program")],
    output: Annotated[Path, typer.Option("--output")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Verify backup integrity, containment, and secret redaction."""
    token = os.environ.get("H1_API_TOKEN")
    result = verify_backup(output, program, configured_token=token)
    if json_output:
        typer.echo(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True))
    else:
        console.print(f"Backup valid: {'yes' if result.valid else 'no'}")
        console.print(f"Reports checked: {result.checked_reports}")
        console.print(f"Attachments checked: {result.checked_attachments}")
        for error in result.errors:
            error_console.print(f"[red]ERROR[/red] {error}")
    if not result.valid:
        raise typer.Exit(1)


@app.command()
def snapshot(
    program: Annotated[str, typer.Option("--program")],
    output: Annotated[Path, typer.Option("--output")],
    destination: Annotated[Path, typer.Option("--destination")],
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    """Create a verified portable ZIP, excluding machine-local state and logs."""
    console.print(
        "Warning: the ZIP contains confidential vulnerability reports; store and share it securely."
    )
    try:
        path, verification = create_snapshot(
            output,
            program,
            destination,
            force=force,
            configured_token=os.environ.get("H1_API_TOKEN"),
        )
        console.print(f"Created {path} (source verification valid: {verification.valid})")
    except H1VaultError as exc:
        _fail(exc)


def _all_reports() -> list[dict[str, Any]]:
    credentials = resolve_credentials()
    with HackerOneClient(
        credentials,
        max_retries=runtime.settings.api.max_retries,
        concurrency=runtime.settings.api.concurrency,
    ) as client:
        return list(client.iter_reports(runtime.settings.api.page_size))


def _report_row(report: dict[str, Any]) -> dict[str, Any]:
    attrs = attributes_of(report)
    return {
        "report_id": str(report["id"]),
        "program_handle": program_handle(report),
        "title": attrs.get("title"),
        "state": attrs.get("state"),
        "severity": relationship_label(report, "severity", "rating", "severity_rating"),
        "creation_date": attrs.get("submitted_at") or attrs.get("created_at"),
        "last_activity_date": attrs.get("last_activity_at"),
        "bounty_total": bounty_total(report),
    }


def _download_single_attachments(
    report: dict[str, Any],
    reports_root: Path,
    program_root: Path,
    client: HackerOneClient,
) -> list[dict[str, Any]]:
    attrs = attributes_of(report)
    title = str(attrs.get("title") or "untitled")
    from h1vault.backup.exporter import choose_report_directory

    directory = choose_report_directory(reports_root, str(report["id"]), title)
    records: list[dict[str, Any]] = []
    max_bytes = runtime.settings.backup.max_attachment_size_mb * 1024 * 1024
    with AttachmentDownloader(max_bytes=max_bytes) as downloader:
        for item in extract_attachments(report):
            item_attrs = attributes_of(item)
            attachment_id = str(item["id"])
            source = str(item.get("_source", "report"))
            activity_id = str(item.get("_activity_id", ""))
            target_dir = (
                directory / "attachments" / "activities" / safe_filename(activity_id)
                if source == "activity"
                else directory / "attachments" / "report"
            )
            target = target_dir / attachment_filename(
                attachment_id, str(item_attrs.get("file_name") or "unnamed")
            )
            record: dict[str, Any] = {
                "key": f"{source}:{activity_id}:{attachment_id}",
                "id": attachment_id,
                "path": target.relative_to(program_root).as_posix(),
                "content_type": item_attrs.get("content_type"),
                "size": item_attrs.get("file_size"),
                "sha256": None,
                "status": "skipped",
                "skip_reason": None,
            }
            url = item_attrs.get("expiring_url")
            if not isinstance(url, str) or not url:
                record["skip_reason"] = "temporary download URL is missing"
            else:
                try:
                    expected_size = _int_or_none(item_attrs.get("file_size"))
                    try:
                        downloaded = downloader.download(url, target, expected_size)
                    except ExpiredAttachmentURLError as exc:
                        refreshed = client.get_report(str(report["id"]))
                        refreshed_url = _single_attachment_url(
                            refreshed, attachment_id, source, activity_id
                        )
                        if not refreshed_url:
                            raise AttachmentDownloadError(
                                f"Attachment {attachment_id} expired and could not be refreshed."
                            ) from exc
                        downloaded = downloader.download(refreshed_url, target, expected_size)
                    record.update(
                        status="downloaded",
                        sha256=downloaded.sha256,
                        size=downloaded.size,
                    )
                except H1VaultError as exc:
                    record["skip_reason"] = str(exc)
            records.append(record)
    return records


def _single_attachment_url(
    report: dict[str, Any], attachment_id: str, source: str, activity_id: str
) -> str | None:
    for item in extract_attachments(report):
        if str(item.get("id")) != attachment_id or str(item.get("_source")) != source:
            continue
        if source == "activity" and str(item.get("_activity_id")) != activity_id:
            continue
        value = attributes_of(item).get("expiring_url")
        return value if isinstance(value, str) and value else None
    return None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _print_status(status: CredentialStatus) -> None:
    console.print(
        f"API-token identifier configured: {'yes' if status.username_configured else 'no'}"
    )
    console.print(f"Token available: {'yes' if status.token_available else 'no'}")
    console.print(f"Active credential source: {status.source}")


def _print_sync_summary(value: dict[str, Any]) -> None:
    console.print(f"H1Vault {__version__}\n")
    labels = (
        ("Program", "program"),
        ("Reports discovered", "reports_discovered"),
        ("New reports", "new_reports"),
        ("Updated reports", "updated_reports"),
        ("Unchanged reports", "unchanged_reports"),
        ("Attachments downloaded", "attachments_downloaded"),
        ("Attachments skipped", "attachments_skipped"),
        ("Errors", "error_count"),
        ("Backup", "backup"),
    )
    for label, key in labels:
        console.print(f"{label}: {value[key]}")


def _guard(operation: Any, *, success: str) -> None:
    try:
        operation()
        console.print(success)
    except H1VaultError as exc:
        _fail(exc)


def _fail(exc: H1VaultError, *, json_output: bool = False) -> None:
    if json_output:
        typer.echo(json.dumps({"error": str(exc), "type": type(exc).__name__}, sort_keys=True))
    else:
        error_console.print(f"[red]Error:[/red] {exc}")
    raise typer.Exit(1) from exc
