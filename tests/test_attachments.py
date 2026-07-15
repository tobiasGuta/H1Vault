from __future__ import annotations

import hashlib
from pathlib import Path

import httpcore
import httpx
import pytest

from h1vault.exceptions import (
    AttachmentDownloadError,
    AttachmentTooLargeError,
    ExpiredAttachmentURLError,
)
from h1vault.security.downloads import (
    AttachmentDownloader,
    PinnedNetworkBackend,
    validate_download_url,
)
from h1vault.security.filenames import attachment_filename


def PUBLIC(_host: str) -> list[str]:
    return ["93.184.216.34"]


def downloader(handler, max_bytes: int = 1024, max_redirects: int = 3):
    return AttachmentDownloader(
        max_bytes=max_bytes,
        max_redirects=max_redirects,
        transport=httpx.MockTransport(handler),
        resolver=PUBLIC,
    )


@pytest.mark.parametrize("content", [b"hello", b""])
def test_normal_and_empty_download(tmp_path: Path, content: bytes) -> None:
    with downloader(lambda _: httpx.Response(200, content=content)) as instance:
        result = instance.download("https://files.example/a", tmp_path / "file.bin")
    assert result.path.read_bytes() == content
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size == len(content)


def test_incorrect_content_length_stream_limit_cleans_part(tmp_path: Path) -> None:
    with downloader(
        lambda _: httpx.Response(200, headers={"Content-Length": "1"}, content=b"too-big"),
        max_bytes=3,
    ) as instance:
        with pytest.raises(AttachmentTooLargeError):
            instance.download("https://files.example/a", tmp_path / "file")
    assert not list(tmp_path.glob("*.part"))
    assert not list(tmp_path.glob(".*.part"))


def test_declared_expected_size_rejected_before_network(tmp_path: Path) -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    with downloader(handler, max_bytes=10) as instance:
        with pytest.raises(AttachmentTooLargeError):
            instance.download("https://files.example/a", tmp_path / "file", expected_size=11)
    assert calls == 0


def test_redirect_is_revalidated_and_limited(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/a":
            return httpx.Response(302, headers={"Location": "https://cdn.example/b"})
        return httpx.Response(200, content=b"ok")

    with downloader(handler) as instance:
        assert instance.download("https://files.example/a", tmp_path / "file").size == 2

    with downloader(
        lambda _: httpx.Response(302, headers={"Location": "/again"}), max_redirects=1
    ) as instance:
        with pytest.raises(AttachmentDownloadError, match="redirect"):
            instance.download("https://files.example/a", tmp_path / "other")


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "0.0.0.0"],
)
def test_non_public_redirect_targets_rejected(address: str) -> None:
    with pytest.raises(AttachmentDownloadError, match="non-public"):
        validate_download_url("https://host.example/a", lambda _: [address])


@pytest.mark.parametrize(
    "url",
    ["http://example.com/a", "file:///tmp/a", "ftp://example.com/a", "https://u:p@example.com/a"],
)
def test_non_https_or_embedded_credentials_rejected(url: str) -> None:
    with pytest.raises(AttachmentDownloadError, match="HTTPS"):
        validate_download_url(url, PUBLIC)


def test_expired_url_has_distinct_error(tmp_path: Path) -> None:
    with downloader(lambda _: httpx.Response(403)) as instance:
        with pytest.raises(ExpiredAttachmentURLError):
            instance.download("https://files.example/a", tmp_path / "file")


def test_attachment_client_does_not_trust_proxy_environment() -> None:
    with downloader(lambda _: httpx.Response(200, content=b"ok")) as instance:
        assert instance.client._trust_env is False


def test_pinned_backend_rejects_dns_rebinding_before_connect() -> None:
    calls = 0

    def rebinding(_host: str) -> list[str]:
        nonlocal calls
        calls += 1
        return ["93.184.216.34"] if calls == 1 else ["127.0.0.1"]

    class RecordingBackend(httpcore.NetworkBackend):
        def __init__(self) -> None:
            self.hosts: list[str] = []

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            self.hosts.append(host)
            raise AssertionError("unsafe address must never reach connect")

        def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise AssertionError("not used")

    validate_download_url("https://rebind.example/a", rebinding)
    recording = RecordingBackend()
    backend = PinnedNetworkBackend(rebinding, recording)
    with pytest.raises(AttachmentDownloadError, match="non-public"):
        backend.connect_tcp("rebind.example", 443)
    assert recording.hosts == []


def test_pinned_backend_connects_to_validated_ip_not_hostname() -> None:
    stream = httpcore.MockStream([])

    class RecordingBackend(httpcore.NetworkBackend):
        def __init__(self) -> None:
            self.host: str | None = None

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            self.host = host
            return stream

        def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise AssertionError("not used")

    recording = RecordingBackend()
    backend = PinnedNetworkBackend(lambda _: ["93.184.216.34"], recording)
    assert backend.connect_tcp("attachment.example", 443) is stream
    assert recording.host == "93.184.216.34"


@pytest.mark.parametrize(
    "original",
    ["../escape", "C:\\absolute.exe", "/absolute", "CON", "name. ", "x" * 500, "résumé.txt"],
)
def test_remote_names_are_safe_and_id_prefixed(original: str) -> None:
    result = attachment_filename("a1", original)
    assert result.startswith("a1_")
    assert "/" not in result and "\\" not in result
    assert len(result) <= 163


def test_destination_symlink_rejected_where_supported(tmp_path: Path) -> None:
    destination = tmp_path / "file"
    try:
        destination.symlink_to(tmp_path / "target")
    except OSError:
        pytest.skip("symlink creation is not permitted")
    with downloader(lambda _: httpx.Response(200, content=b"bad")) as instance:
        with pytest.raises(Exception, match="symlink"):
            instance.download("https://files.example/a", destination)
