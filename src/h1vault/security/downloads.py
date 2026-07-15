"""Streaming attachment downloads with SSRF and path protections."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
import socket
import ssl
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpcore
import httpx

from h1vault.exceptions import (
    AttachmentDownloadError,
    AttachmentTooLargeError,
    ExpiredAttachmentURLError,
    UnsafeAttachmentPathError,
)
from h1vault.security.filenames import ensure_within


@dataclass(frozen=True)
class DownloadResult:
    path: Path
    sha256: str
    size: int
    content_type: str | None


Resolver = Callable[[str], Iterable[str]]


def resolve_addresses(hostname: str) -> Iterable[str]:
    return {str(item[4][0]) for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}


def validate_download_url(url: str, resolver: Resolver = resolve_addresses) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise AttachmentDownloadError("Attachment URL must be credential-free HTTPS.")
    _validated_addresses(parsed.hostname, resolver)


def _validated_addresses(hostname: str, resolver: Resolver) -> list[str]:
    try:
        addresses = sorted(set(resolver(hostname)))
    except OSError as exc:
        raise AttachmentDownloadError("Attachment host could not be resolved safely.") from exc
    if not addresses:
        raise AttachmentDownloadError("Attachment host did not resolve to an address.")
    validated: list[str] = []
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError as exc:
            raise AttachmentDownloadError(
                "Attachment host resolved to an invalid address."
            ) from exc
        if not address.is_global:
            raise AttachmentDownloadError(
                "Attachment URL resolves to a non-public network address."
            )
        validated.append(str(address))
    return validated


class PinnedNetworkBackend(httpcore.NetworkBackend):
    """Resolve, validate, and connect to the same IP to prevent DNS rebinding."""

    def __init__(self, resolver: Resolver, backend: httpcore.NetworkBackend | None = None) -> None:
        self._resolver = resolver
        self._backend = backend or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = _validated_addresses(host, self._resolver)
        last_error: Exception | None = None
        for address in addresses:
            try:
                return self._backend.connect_tcp(
                    address, port, timeout, local_address, socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise AttachmentDownloadError("Attachment host had no safe connectable address.")

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise AttachmentDownloadError("Unix sockets are not valid attachment destinations.")

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)


class PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTPX transport using an address-pinning httpcore network backend."""

    def __init__(self, resolver: Resolver) -> None:
        super().__init__(verify=True, trust_env=False)
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=3,
            max_keepalive_connections=3,
            network_backend=PinnedNetworkBackend(resolver),
        )


class AttachmentDownloader:
    """Anonymous attachment downloader; HackerOne credentials never enter this client."""

    def __init__(
        self,
        *,
        max_bytes: int,
        max_redirects: int = 3,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver = resolve_addresses,
    ) -> None:
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.resolver = resolver
        self.client = httpx.Client(
            timeout=httpx.Timeout(connect=10, read=60, write=60, pool=10),
            limits=httpx.Limits(max_connections=3, max_keepalive_connections=3),
            follow_redirects=False,
            verify=True,
            trust_env=False,
            headers={"User-Agent": "H1Vault attachment downloader"},
            transport=transport or PinnedHTTPTransport(resolver),
        )

    def __enter__(self) -> AttachmentDownloader:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self.client.close()

    def download(
        self, url: str, destination: Path, expected_size: int | None = None
    ) -> DownloadResult:
        """Stream one untrusted file to an atomic destination and return its digest."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._validate_destination(destination)
        if expected_size is not None and expected_size > self.max_bytes:
            raise AttachmentTooLargeError(
                f"Attachment declares {expected_size} bytes, above the {self.max_bytes}-byte limit."
            )
        part = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.part")
        ensure_within(part, destination.parent)
        current = url
        try:
            for redirect in range(self.max_redirects + 1):
                validate_download_url(current, self.resolver)
                with self.client.stream("GET", current) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        location = response.headers.get("Location")
                        if not location or redirect >= self.max_redirects:
                            raise AttachmentDownloadError(
                                "Attachment redirect limit exceeded or location missing."
                            )
                        current = urljoin(current, location)
                        continue
                    if response.status_code == 403:
                        raise ExpiredAttachmentURLError(
                            "The temporary attachment URL was rejected or expired."
                        )
                    if response.status_code >= 400:
                        raise AttachmentDownloadError(
                            f"Attachment host returned HTTP {response.status_code}."
                        )
                    declared = response.headers.get("Content-Length")
                    if declared:
                        try:
                            if int(declared) > self.max_bytes:
                                raise AttachmentTooLargeError(
                                    "Attachment Content-Length exceeds the "
                                    f"{self.max_bytes}-byte limit."
                                )
                        except ValueError:
                            pass
                    return self._write_stream(
                        response.iter_bytes(),
                        part,
                        destination,
                        response.headers.get("Content-Type"),
                    )
            raise AttachmentDownloadError("Attachment redirect processing failed.")
        except Exception:
            part.unlink(missing_ok=True)
            raise

    def _write_stream(
        self, chunks: Iterable[bytes], part: Path, destination: Path, content_type: str | None
    ) -> DownloadResult:
        digest = hashlib.sha256()
        size = 0
        try:
            with part.open("xb") as target:
                for chunk in chunks:
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise AttachmentTooLargeError(
                            f"Attachment exceeded the {self.max_bytes}-byte streaming limit."
                        )
                    target.write(chunk)
                    digest.update(chunk)
                target.flush()
                os.fsync(target.fileno())
            os.replace(part, destination)
        except OSError as exc:
            raise AttachmentDownloadError(
                f"Could not write attachment {destination.name}: {exc}"
            ) from exc
        return DownloadResult(destination, digest.hexdigest(), size, content_type)

    @staticmethod
    def _validate_destination(destination: Path) -> None:
        ensure_within(destination, destination.parent)
        if destination.exists() and destination.is_symlink():
            raise UnsafeAttachmentPathError("Refusing to replace an attachment symlink.")
        current = destination.parent
        while current != current.parent:
            if current.is_symlink():
                raise UnsafeAttachmentPathError("Refusing an attachment path containing a symlink.")
            current = current.parent
