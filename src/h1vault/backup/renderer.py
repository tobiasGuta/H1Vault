"""Readable Markdown rendering for flexible HackerOne report resources."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from h1vault.api.models import program_handle, relationship_data


def attributes_of(value: Any) -> dict[str, Any]:
    return value.get("attributes", {}) if isinstance(value, dict) else {}


def scalar(value: Any, default: str = "Unknown") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        import json

        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def relationship_label(report: dict[str, Any], name: str, *keys: str) -> str:
    related = relationship_data(report, name)
    attrs = attributes_of(related)
    for key in keys:
        if attrs.get(key) is not None:
            return scalar(attrs[key])
    if isinstance(related, dict) and related.get("id") is not None:
        return str(related["id"])
    return "Unknown"


def extract_activities(report: dict[str, Any]) -> list[dict[str, Any]]:
    raw = relationship_data(report, "activities")
    activities = [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []
    return sorted(
        activities,
        key=lambda item: str(attributes_of(item).get("created_at") or "9999-12-31T23:59:59Z"),
    )


def extract_attachments(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect direct and per-activity attachment resources with stable source metadata."""
    found: dict[tuple[str, str], dict[str, Any]] = {}
    direct = relationship_data(report, "attachments")
    for item in direct if isinstance(direct, list) else []:
        if isinstance(item, dict) and item.get("id") is not None:
            copy = dict(item)
            copy["_source"] = "report"
            found[("report", str(item["id"]))] = copy
    for activity in extract_activities(report):
        activity_id = str(activity.get("id", "unknown"))
        nested = relationship_data(activity, "attachments")
        for item in nested if isinstance(nested, list) else []:
            if isinstance(item, dict) and item.get("id") is not None:
                copy = dict(item)
                copy["_source"] = "activity"
                copy["_activity_id"] = activity_id
                found[(f"activity:{activity_id}", str(item["id"]))] = copy
    return list(found.values())


def bounty_total(report: dict[str, Any]) -> str | None:
    bounties = relationship_data(report, "bounties")
    if not isinstance(bounties, list):
        return None
    total = Decimal("0")
    known = False
    for bounty in bounties:
        attrs = attributes_of(bounty)
        for key in ("amount", "bonus_amount"):
            try:
                if attrs.get(key) is not None:
                    total += Decimal(str(attrs[key]))
                    known = True
            except InvalidOperation:
                continue
    return f"{total:.2f}" if known else None


def render_original(report: dict[str, Any]) -> str:
    attrs = attributes_of(report)
    body = str(attrs.get("vulnerability_information") or "")
    impact = attrs.get("impact")
    if impact:
        separator = "\n" if body.endswith("\n") else "\n\n"
        return f"{body}{separator}## Impact\n\n{impact}"
    return body


def render_report(
    report: dict[str, Any], *, synchronized_at: str, attachment_records: list[dict[str, Any]]
) -> str:
    attrs = attributes_of(report)
    title = scalar(attrs.get("title"), "Untitled report")
    report_id = str(report.get("id", "unknown"))
    handle = program_handle(report) or "Unknown"
    lines = [
        f"# {title}",
        "",
        "> This is a sanitized human-readable presentation. Use `report.raw.json` and "
        "`original-report.md` for evidence-preserving content.",
        "",
        "## Metadata",
        "",
        f"- Report ID: {report_id}",
        f"- Program: {handle}",
        f"- HackerOne URL: https://hackerone.com/reports/{report_id}",
        f"- State: {scalar(attrs.get('state'))}",
        f"- Severity: {relationship_label(report, 'severity', 'rating', 'severity_rating')}",
        f"- Weakness: {relationship_label(report, 'weakness', 'name')}",
        "- Structured scope or asset: "
        f"{relationship_label(report, 'structured_scope', 'asset_identifier')}",
        f"- Submitted date: {scalar(attrs.get('submitted_at') or attrs.get('created_at'))}",
        f"- Triaged date: {scalar(attrs.get('triaged_at'))}",
        f"- Closed date: {scalar(attrs.get('closed_at'))}",
        f"- Disclosed date: {scalar(attrs.get('disclosed_at'))}",
        f"- Last activity date: {scalar(attrs.get('last_activity_at'))}",
        f"- Total bounty: {bounty_total(report) or 'Unknown'}",
        f"- Reporter: {relationship_label(report, 'reporter', 'username', 'name')}",
        f"- Local synchronization date: {synchronized_at}",
        "",
        "## Vulnerability Information",
        "",
        str(
            attrs.get("vulnerability_information")
            or "_Not present in the accessible API response._"
        ),
        "",
        "## Impact",
        "",
        str(attrs.get("impact") or "_Not supplied separately._"),
        "",
        "## Severity",
        "",
        relationship_label(report, "severity", "rating", "severity_rating", "score"),
        "",
        "## Scope",
        "",
        relationship_label(report, "structured_scope", "asset_identifier", "asset_type"),
        "",
        "## Bounties",
        "",
    ]
    lines.extend(_resource_bullets(relationship_data(report, "bounties")))
    lines.extend(["", "## Summaries", ""])
    lines.extend(_resource_bullets(relationship_data(report, "summaries")))
    lines.extend(["", "## Timeline", ""])
    activities = extract_activities(report)
    if not activities:
        lines.append("_No visible activities._")
    for activity in activities:
        a = attributes_of(activity)
        when = scalar(a.get("created_at"))
        kind = scalar(activity.get("type"), "activity")
        internal = " **[internal/private]**" if a.get("internal") or a.get("private") else ""
        message = a.get("message") or a.get("content") or a.get("comment") or ""
        lines.extend([f"### {when} — {kind}{internal}", "", str(message), ""])
    lines.extend(["## Attachments", ""])
    if not attachment_records:
        lines.append("_No attachments recorded._")
    for record in attachment_records:
        suffixes: list[str] = []
        if record.get("skip_reason"):
            suffixes.append(f"skipped: {record['skip_reason']}")
        if record.get("historical_reason"):
            suffixes.append(
                f"historical; not present in latest API response: {record['historical_reason']}"
            )
        lines.append(
            (
                "- `{path}` — ID `{id}`, type `{content_type}`, size {size}, "
                "SHA-256 `{sha256}`{suffix}"
            ).format(
                path=record.get("path") or "not downloaded",
                id=record.get("id", "unknown"),
                content_type=record.get("content_type") or "unknown",
                size=record.get("size") if record.get("size") is not None else "unknown",
                sha256=record.get("sha256") or "not available",
                suffix=f" ({'; '.join(suffixes)})" if suffixes else "",
            )
        )
    return "\n".join(lines).rstrip() + "\n"


def _resource_bullets(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return ["_None visible._"]
    result: list[str] = []
    for item in value:
        attrs = attributes_of(item)
        result.append(f"- {scalar(attrs)}")
    return result
