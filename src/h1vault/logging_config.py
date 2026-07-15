"""Secret-safe human and optional structured logging."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

from h1vault.security.redaction import redact_text


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        secrets = tuple(value for value in (os.environ.get("H1_API_TOKEN"),) if value is not None)
        record.msg = redact_text(record.getMessage(), secrets)
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            },
            ensure_ascii=False,
            sort_keys=True,
        )


def configure_logging(level: str, log_file: Path | None = None) -> None:
    handlers: list[logging.Handler] = []
    stream = logging.StreamHandler(sys.__stderr__)
    stream.addFilter(RedactionFilter())
    handlers.append(stream)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        file_handler.addFilter(RedactionFilter())
        handlers.append(file_handler)
    logging.basicConfig(
        level=level, handlers=handlers, force=True, format="%(levelname)s %(message)s"
    )
