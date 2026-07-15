from __future__ import annotations

import base64

import httpx
import pytest
import respx

from h1vault.api.client import HackerOneClient
from h1vault.credentials import Credentials
from h1vault.exceptions import (
    APIResponseError,
    AuthenticationError,
    AuthorizationError,
    InvalidAPIResponseError,
    NotFoundError,
    RateLimitError,
)


def client(handler, **kwargs):
    return HackerOneClient(
        Credentials("identifier", "token-value", "test"),
        transport=httpx.MockTransport(handler),
        sleep=lambda _: None,
        jitter=lambda: 0.0,
        **kwargs,
    )


def test_basic_auth_and_headers_are_attached() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        expected = base64.b64encode(b"identifier:token-value").decode()
        assert request.headers["Authorization"] == f"Basic {expected}"
        assert request.headers["Accept"] == "application/json"
        assert request.headers["User-Agent"].startswith("H1Vault/")
        return httpx.Response(200, json={"data": []})

    with client(handler) as api:
        api.doctor_request()


@respx.mock
def test_respx_intercepts_official_endpoint_without_real_network() -> None:
    route = respx.get("https://api.hackerone.com/v1/hackers/me/reports").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    with HackerOneClient(Credentials("identifier", "token", "test")) as api:
        api.doctor_request()
    assert route.called


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_authenticated_client_rejects_write_methods(method: str) -> None:
    with client(lambda _: httpx.Response(200)) as api:
        with pytest.raises(ValueError, match="only GET and HEAD"):
            api.request(method, "hackers/me/reports")


def test_client_refuses_credential_exfiltration() -> None:
    with client(lambda _: httpx.Response(200)) as api:
        with pytest.raises(ValueError, match="different origin"):
            api.request("GET", "https://evil.example/path")


@pytest.mark.parametrize(
    ("status", "exception"),
    [
        (401, AuthenticationError),
        (403, AuthorizationError),
        (404, NotFoundError),
        (429, RateLimitError),
        (400, APIResponseError),
    ],
)
def test_status_mapping(status: int, exception: type[Exception]) -> None:
    with client(lambda _: httpx.Response(status), max_retries=0) as api:
        with pytest.raises(exception):
            api.request("GET", "hackers/me/reports")


def test_retries_5xx_then_succeeds() -> None:
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503 if attempts < 3 else 200, json={"data": []})

    with client(handler, max_retries=4) as api:
        api.doctor_request()
    assert attempts == 3


def test_retry_after_is_honored() -> None:
    delays: list[float] = []
    attempts = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(
            429 if attempts == 1 else 200,
            headers={"Retry-After": "7"},
            json={"data": []},
        )

    api = HackerOneClient(
        Credentials("u", "t", "test"),
        transport=httpx.MockTransport(handler),
        sleep=delays.append,
        jitter=lambda: 0,
    )
    with api:
        api.doctor_request()
    assert delays == [7.0]


def test_invalid_json() -> None:
    with client(lambda _: httpx.Response(200, text="not-json")) as api:
        with pytest.raises(InvalidAPIResponseError, match="invalid JSON"):
            api.get_json("hackers/me/reports")


def test_timeout_is_actionable_after_retry() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    with client(handler, max_retries=1) as api:
        with pytest.raises(APIResponseError, match="could not be reached"):
            api.get_json("hackers/me/reports")


def test_unknown_fields_are_preserved(report_factory) -> None:
    report = report_factory()
    report["attributes"]["future_field"] = {"nested": True}
    with client(lambda _: httpx.Response(200, json={"data": report})) as api:
        detail = api.get_report("123")
    assert detail["attributes"]["future_field"] == {"nested": True}


def test_detailed_response_preserves_complete_top_level_document(report_factory) -> None:
    report = report_factory()
    document = {
        "data": report,
        "included": [{"id": "included-1", "type": "user"}],
        "meta": {"future": True},
        "links": {"self": "https://api.hackerone.com/v1/hackers/reports/123"},
    }
    with client(lambda _: httpx.Response(200, json=document)) as api:
        response = api.get_report_response("123")
    assert response.resource is response.raw_document["data"]
    assert response.raw_document == document


def test_tls_verification_cannot_be_disabled() -> None:
    with pytest.raises(TypeError):
        HackerOneClient(Credentials("u", "t", "test"), verify=False)  # type: ignore[call-arg]


def test_authenticated_client_does_not_trust_proxy_environment() -> None:
    with client(lambda _: httpx.Response(200, json={"data": []})) as api:
        assert api._client._trust_env is False
