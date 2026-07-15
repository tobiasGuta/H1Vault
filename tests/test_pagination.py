from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from h1vault.api.client import HackerOneClient
from h1vault.credentials import Credentials
from h1vault.exceptions import APIResponseError, InvalidAPIResponseError


def make_client(handler):
    return HackerOneClient(
        Credentials("u", "t", "test"),
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
        max_retries=0,
    )


def resource(number: int) -> dict[str, object]:
    return {"id": str(number), "type": "report", "attributes": {}, "relationships": {}}


def test_one_page_and_empty_final_page() -> None:
    pages: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        page = int(parse_qs(request.url.query.decode())["page[number]"][0])
        pages.append(page)
        data = [resource(i) for i in range(100)] if page == 1 else []
        return httpx.Response(200, json={"data": data})

    with make_client(handler) as api:
        assert len(list(api.iter_reports())) == 100
    assert pages == [1, 2]


def test_multiple_incrementing_pages() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        page = int(parse_qs(request.url.query.decode())["page[number]"][0])
        start = (page - 1) * 2
        return httpx.Response(200, json={"data": [resource(start), resource(start + 1)]})

    with make_client(handler) as api:
        assert [item["id"] for item in api.iter_reports(page_size=3)] == ["0", "1"]


def test_next_link_pagination_and_duplicate_ids() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "page=2" in str(request.url):
            return httpx.Response(200, json={"data": [resource(2)], "links": {"next": None}})
        return httpx.Response(
            200,
            json={
                "data": [resource(1), resource(1)],
                "links": {"next": "https://api.hackerone.com/v1/hackers/me/reports?page=2"},
            },
        )

    with make_client(handler) as api:
        assert [item["id"] for item in api.iter_reports()] == ["1", "2"]


def test_repeated_next_link_is_rejected() -> None:
    next_url = "https://api.hackerone.com/v1/hackers/me/reports?page=2"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [resource(1)], "links": {"next": next_url}})

    with make_client(handler) as api, pytest.raises(InvalidAPIResponseError, match="repeated"):
        list(api.iter_reports())


@pytest.mark.parametrize("body", [{}, {"data": None}, {"data": {}}, {"data": "bad"}])
def test_malformed_responses(body: dict[str, object]) -> None:
    with make_client(lambda _: httpx.Response(200, json=body)) as api:
        with pytest.raises(InvalidAPIResponseError, match="Malformed"):
            list(api.iter_reports())


def test_network_failure_halfway_is_not_silently_truncated() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise httpx.ConnectError("broken", request=request)
        return httpx.Response(200, json={"data": [resource(i) for i in range(100)]})

    with make_client(handler) as api, pytest.raises(APIResponseError):
        list(api.iter_reports())
