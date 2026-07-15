"""Permissive models for an additive JSON:API contract."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Resource(BaseModel):
    """A minimally validated resource that preserves future fields."""

    model_config = ConfigDict(extra="allow")
    id: str
    type: str = "unknown"
    attributes: dict[str, Any] = Field(default_factory=dict)
    relationships: dict[str, Any] = Field(default_factory=dict)
    links: dict[str, Any] = Field(default_factory=dict)


class ResourceCollection(BaseModel):
    model_config = ConfigDict(extra="allow")
    data: list[Resource]
    links: dict[str, Any] = Field(default_factory=dict)


class ResourceDocument(BaseModel):
    model_config = ConfigDict(extra="allow")
    data: Resource


def relationship_data(resource: dict[str, Any], name: str) -> Any:
    relationship = resource.get("relationships", {}).get(name, {})
    return relationship.get("data") if isinstance(relationship, dict) else None


def program_handle(resource: dict[str, Any]) -> str | None:
    program = relationship_data(resource, "program")
    if not isinstance(program, dict):
        return None
    attributes = program.get("attributes")
    if not isinstance(attributes, dict):
        return None
    value = attributes.get("handle") or attributes.get("team_handle")
    return str(value) if value is not None else None


def normalize_handle(value: str) -> str:
    return value.strip().casefold()


def filter_program(resources: list[dict[str, Any]], handle: str) -> list[dict[str, Any]]:
    wanted = normalize_handle(handle)
    return [
        item
        for item in resources
        if (found := program_handle(item)) and normalize_handle(found) == wanted
    ]
