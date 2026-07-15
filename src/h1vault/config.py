"""Validated configuration with CLI/environment/file/default precedence."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from platformdirs import user_config_path
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from h1vault.exceptions import ConfigurationError


class APISettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    page_size: int = Field(default=100, ge=1, le=100)
    max_retries: int = Field(default=4, ge=0, le=10)
    concurrency: int = Field(default=3, ge=1, le=10)


class BackupSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    default_output: Path = Path("HackerOneBackups")
    include_attachments: bool = True
    max_attachment_size_mb: int = Field(default=1024, ge=0, le=102400)


class LoggingSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR)$")


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api: APISettings = APISettings()
    backup: BackupSettings = BackupSettings()
    logging: LoggingSettings = LoggingSettings()


def config_path() -> Path:
    return user_config_path("h1vault", appauthor=False) / "config.toml"


def load_settings(path: Path | None = None) -> Settings:
    """Load validated configuration, applying supported environment overrides."""
    target = path or config_path()
    raw: dict[str, Any] = {}
    if target.exists():
        try:
            loaded = tomllib.loads(target.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigurationError(f"Could not read configuration {target}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigurationError("The configuration root must be a TOML table.")
        raw = loaded
    _env_override(raw, "api", "page_size", "H1VAULT_PAGE_SIZE", int)
    _env_override(raw, "api", "max_retries", "H1VAULT_MAX_RETRIES", int)
    _env_override(raw, "api", "concurrency", "H1VAULT_CONCURRENCY", int)
    _env_override(raw, "backup", "default_output", "H1VAULT_OUTPUT", str)
    _env_override(raw, "backup", "max_attachment_size_mb", "H1VAULT_MAX_ATTACHMENT_SIZE_MB", int)
    include = os.environ.get("H1VAULT_INCLUDE_ATTACHMENTS")
    if include is not None:
        normalized = include.strip().casefold()
        if normalized not in {"true", "false", "1", "0", "yes", "no"}:
            raise ConfigurationError(
                "H1VAULT_INCLUDE_ATTACHMENTS must be true/false, yes/no, or 1/0."
            )
        raw.setdefault("backup", {})["include_attachments"] = normalized in {
            "true",
            "1",
            "yes",
        }
    _env_override(raw, "logging", "level", "H1VAULT_LOG_LEVEL", str)
    try:
        return Settings.model_validate(raw)
    except (ValidationError, ValueError) as exc:
        raise ConfigurationError(f"Invalid H1Vault configuration: {exc}") from exc


def _env_override(
    raw: dict[str, Any], section: str, key: str, name: str, convert: type[int] | type[str]
) -> None:
    value = os.environ.get(name)
    if value is not None:
        raw.setdefault(section, {})[key] = convert(value)
