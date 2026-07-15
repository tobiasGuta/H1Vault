from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture
def report_factory():
    def make(
        report_id: str = "123",
        *,
        program: str = "example-program",
        title: str = "Example report",
        state: str = "triaged",
        last_activity: str = "2026-01-02T00:00:00Z",
        relationships: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rels: dict[str, Any] = {
            "program": {
                "data": {
                    "id": "p1",
                    "type": "program",
                    "attributes": {"handle": program, "name": "Example"},
                }
            },
            "activities": {"data": []},
            "attachments": {"data": []},
            "bounties": {"data": []},
            "summaries": {"data": []},
        }
        if relationships:
            rels.update(relationships)
        return {
            "id": report_id,
            "type": "report",
            "attributes": {
                "title": title,
                "state": state,
                "created_at": "2026-01-01T00:00:00Z",
                "last_activity_at": last_activity,
                "vulnerability_information": "**original** markdown",
                "impact": "Impact text",
            },
            "relationships": rels,
        }

    return make
