"""Credential resolution without command-line secrets or browser data."""

from __future__ import annotations

import os
from dataclasses import dataclass

import keyring
from keyring.errors import KeyringError

from h1vault.exceptions import AuthenticationError, CredentialStorageError

SERVICE = "h1vault.hackerone"
USERNAME_KEY = "api-token-identifier"
TOKEN_KEY = "api-token-value"  # noqa: S105 - keyring account label, not a credential


@dataclass(frozen=True)
class Credentials:
    username: str
    token: str
    source: str


@dataclass(frozen=True)
class CredentialStatus:
    username_configured: bool
    token_available: bool
    source: str


def resolve_credentials() -> Credentials:
    """Resolve an all-or-nothing credential pair, preferring environment values."""
    env_user = os.environ.get("H1_API_USERNAME")
    env_token = os.environ.get("H1_API_TOKEN")
    if env_user is not None or env_token is not None:
        if not env_user or not env_token:
            raise AuthenticationError(
                "Set both H1_API_USERNAME and H1_API_TOKEN; a partial environment credential "
                "pair cannot be used."
            )
        return Credentials(env_user, env_token, "environment")
    try:
        username = keyring.get_password(SERVICE, USERNAME_KEY)
        token = keyring.get_password(SERVICE, TOKEN_KEY)
    except KeyringError as exc:
        raise CredentialStorageError(f"The OS keyring is unavailable: {exc}") from exc
    if not username or not token:
        raise AuthenticationError(
            "No HackerOne API credentials are configured. Set H1_API_USERNAME and "
            "H1_API_TOKEN, or run `h1vault auth set`."
        )
    return Credentials(username, token, "OS keyring")


def credential_status() -> CredentialStatus:
    env_user = os.environ.get("H1_API_USERNAME")
    env_token = os.environ.get("H1_API_TOKEN")
    if env_user is not None or env_token is not None:
        return CredentialStatus(bool(env_user), bool(env_token), "environment")
    try:
        username = keyring.get_password(SERVICE, USERNAME_KEY)
        token = keyring.get_password(SERVICE, TOKEN_KEY)
    except KeyringError as exc:
        raise CredentialStorageError(f"The OS keyring is unavailable: {exc}") from exc
    source = "OS keyring" if username or token else "none"
    return CredentialStatus(bool(username), bool(token), source)


def store_credentials(username: str, token: str) -> None:
    if not username or not token:
        raise AuthenticationError("The API-token identifier and token value must not be empty.")
    try:
        keyring.set_password(SERVICE, USERNAME_KEY, username)
        keyring.set_password(SERVICE, TOKEN_KEY, token)
    except KeyringError as exc:
        raise CredentialStorageError(
            f"Could not store credentials in the OS keyring: {exc}"
        ) from exc


def clear_credentials() -> None:
    """Delete keyring entries only; environment values are intentionally untouched."""
    for name in (USERNAME_KEY, TOKEN_KEY):
        try:
            if keyring.get_password(SERVICE, name) is not None:
                keyring.delete_password(SERVICE, name)
        except KeyringError as exc:
            raise CredentialStorageError(f"Could not clear OS-keyring credentials: {exc}") from exc
