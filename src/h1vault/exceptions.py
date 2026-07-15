"""Actionable application exceptions."""


class H1VaultError(Exception):
    """Base class for expected H1Vault failures."""


class AuthenticationError(H1VaultError):
    """Credentials are missing or rejected."""


class AuthorizationError(H1VaultError):
    """The account cannot access a requested resource."""


class NotFoundError(H1VaultError):
    """A requested accessible resource was not found."""


class RateLimitError(H1VaultError):
    """The API continued rate-limiting after retries."""


class APIResponseError(H1VaultError):
    """The API returned an unexpected error status."""


class InvalidAPIResponseError(H1VaultError):
    """The API response was not valid JSON:API data."""


class ProgramNotFoundInReportsError(H1VaultError):
    """No owned report matched a requested program."""


class AttachmentDownloadError(H1VaultError):
    """An attachment could not be downloaded safely."""


class AttachmentTooLargeError(AttachmentDownloadError):
    """An attachment exceeds the configured byte limit."""


class ExpiredAttachmentURLError(AttachmentDownloadError):
    """A temporary attachment URL appears to have expired."""


class UnsafeAttachmentPathError(AttachmentDownloadError):
    """An attachment filename or destination is unsafe."""


class BackupIntegrityError(H1VaultError):
    """A local backup failed integrity verification."""


class CredentialStorageError(H1VaultError):
    """The operating-system credential store failed."""


class ConfigurationError(H1VaultError):
    """Configuration is invalid."""
