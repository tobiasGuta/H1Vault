"""Pagination helpers are implemented by :class:`HackerOneClient`."""

from collections.abc import Iterator
from typing import Any

from h1vault.api.client import HackerOneClient


def iter_owned_reports(client: HackerOneClient, page_size: int = 100) -> Iterator[dict[str, Any]]:
    return client.iter_reports(page_size)
