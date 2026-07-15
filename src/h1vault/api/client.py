"""Strictly read-only, retrying HackerOne API client."""

from __future__ import annotations

import email.utils
import logging
import random
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from h1vault import __version__
from h1vault.api.models import ResourceCollection, ResourceDocument
from h1vault.credentials import Credentials
from h1vault.exceptions import (
    APIResponseError,
    AuthenticationError,
    AuthorizationError,
    InvalidAPIResponseError,
    NotFoundError,
    RateLimitError,
)

LOGGER = logging.getLogger(__name__)
API_BASE = "https://api.hackerone.com/v1/"
ALLOWED_METHODS = frozenset({"GET", "HEAD"})
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})


class HackerOneClient:
    """A HackerOne client whose public request boundary permits GET and HEAD only."""

    def __init__(
        self,
        credentials: Credentials,
        *,
        max_retries: int = 4,
        concurrency: int = 3,
        base_url: str = API_BASE,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("The HackerOne API base URL must be HTTPS.")
        if not 1 <= concurrency <= 10:
            raise ValueError("concurrency must be between 1 and 10")
        self.base_url = base_url.rstrip("/") + "/"
        self.max_retries = max_retries
        self._sleep: Callable[[float], None] = sleep
        self._jitter: Callable[[], float] = jitter
        self._origin = (parsed.scheme, parsed.hostname, parsed.port or 443)
        self._client = httpx.Client(
            base_url=self.base_url,
            auth=httpx.BasicAuth(credentials.username, credentials.token),
            headers={"Accept": "application/json", "User-Agent": f"H1Vault/{__version__}"},
            timeout=httpx.Timeout(connect=10, read=60, write=60, pool=10),
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
            follow_redirects=False,
            verify=True,
            trust_env=False,
            transport=transport,
        )

    def __enter__(self) -> HackerOneClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Send an allowed idempotent request, with bounded retries."""
        normalized_method = method.upper()
        if normalized_method not in ALLOWED_METHODS:
            raise ValueError(
                f"Unauthorized HTTP method: {normalized_method}; only GET and HEAD are allowed."
            )
        resolved = urljoin(self.base_url, url)
        parsed = urlparse(resolved)
        origin = (parsed.scheme, parsed.hostname, parsed.port or 443)
        if origin != self._origin:
            raise ValueError("Refusing to send HackerOne credentials to a different origin.")
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.request(normalized_method, resolved, **kwargs)
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt >= self.max_retries:
                    raise APIResponseError(
                        "The HackerOne API could not be reached after retries. Check the network, "
                        "proxy, and TLS configuration."
                    ) from exc
                self._sleep(self._backoff(attempt, None))
                continue
            if response.status_code in RETRYABLE_STATUSES and attempt < self.max_retries:
                delay = self._backoff(attempt, response.headers.get("Retry-After"))
                LOGGER.warning(
                    "Retrying idempotent HackerOne request after HTTP %s", response.status_code
                )
                self._sleep(delay)
                continue
            return self._raise_for_status(response)
        raise AssertionError("unreachable")

    def get_json(self, url: str, **kwargs: Any) -> dict[str, Any]:
        response = self.request("GET", url, **kwargs)
        try:
            data = response.json()
        except ValueError as exc:
            raise InvalidAPIResponseError("HackerOne returned invalid JSON.") from exc
        if not isinstance(data, dict):
            raise InvalidAPIResponseError("HackerOne returned a non-object JSON response.")
        return data

    def iter_reports(self, page_size: int = 100) -> Iterator[dict[str, Any]]:
        """Yield every unique owned report across either pagination style."""
        if not 1 <= page_size <= 100:
            raise ValueError("page_size must be between 1 and 100")
        page = 1
        next_url: str | None = "hackers/me/reports"
        use_links = False
        seen_links: set[str] = set()
        seen_ids: set[str] = set()
        seen_pages: set[tuple[str, ...]] = set()
        while next_url is not None:
            pagination_key = next_url if use_links else f"{next_url}#page={page}"
            if pagination_key in seen_links:
                raise InvalidAPIResponseError(
                    "Pagination repeated a next link; refusing an infinite loop."
                )
            seen_links.add(pagination_key)
            params = None if use_links else {"page[number]": page, "page[size]": page_size}
            raw = self.get_json(next_url, params=params)
            try:
                collection = ResourceCollection.model_validate(raw)
            except Exception as exc:
                raise InvalidAPIResponseError(
                    "Malformed report-list response: expected a data array."
                ) from exc
            items = [item.model_dump(mode="json", exclude_none=False) for item in collection.data]
            page_ids = tuple(item["id"] for item in items)
            if page_ids and page_ids in seen_pages:
                raise InvalidAPIResponseError(
                    "Pagination repeated an entire report page; refusing an infinite loop."
                )
            seen_pages.add(page_ids)
            for item in items:
                report_id = item["id"]
                if report_id not in seen_ids:
                    seen_ids.add(report_id)
                    yield item
            next_link = collection.links.get("next")
            if next_link is not None:
                if not isinstance(next_link, str) or not next_link:
                    raise InvalidAPIResponseError("Pagination supplied a malformed next link.")
                next_url = next_link
                use_links = True
                page += 1
            elif not items or len(items) < page_size:
                next_url = None
            else:
                page += 1
                next_url = "hackers/me/reports"
                use_links = False

    def get_report(self, report_id: str) -> dict[str, Any]:
        raw = self.get_json(f"hackers/reports/{report_id}")
        try:
            document = ResourceDocument.model_validate(raw)
        except Exception as exc:
            raise InvalidAPIResponseError("Malformed detailed-report response.") from exc
        return document.data.model_dump(mode="json", exclude_none=False)

    def doctor_request(self) -> None:
        self.get_json("hackers/me/reports", params={"page[number]": 1, "page[size]": 1})

    def _raise_for_status(self, response: httpx.Response) -> httpx.Response:
        status = response.status_code
        if status < 400:
            return response
        if status == 401:
            raise AuthenticationError(
                "HackerOne rejected the configured API credentials. Generate or configure a "
                "valid personal HackerOne API token."
            )
        if status == 403:
            raise AuthorizationError(
                "HackerOne denied access to this resource for the authenticated account."
            )
        if status == 404:
            raise NotFoundError(
                "The requested report was not found or is not visible to this account."
            )
        if status == 429:
            raise RateLimitError(
                "HackerOne continued rate-limiting the request after bounded retries."
            )
        raise APIResponseError(f"HackerOne returned HTTP {status} for a read-only request.")

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(300.0, max(0.0, float(retry_after)))
            except ValueError:
                try:
                    parsed = email.utils.parsedate_to_datetime(retry_after)
                    if parsed is None:
                        raise ValueError("invalid Retry-After date")
                    return min(300.0, max(0.0, (parsed - datetime.now(UTC)).total_seconds()))
                except (TypeError, ValueError):
                    pass
        return float(min(30.0, (2**attempt) + self._jitter()))
