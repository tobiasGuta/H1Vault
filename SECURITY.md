# H1Vault security

## Reporting a vulnerability

Do not include private HackerOne report contents, API tokens, or live temporary attachment URLs
in a public issue. Contact the project maintainers privately through the security-reporting method
published for the repository. Include a minimal redacted reproducer and the affected version.

## Credentials

H1Vault accepts a personal API-token identifier and value from `H1_API_USERNAME` and
`H1_API_TOKEN`, or from the operating-system keyring. Environment values take precedence. Tokens
are never accepted as command-line options and are not placed in SQLite, exports, logs, or ZIP
archives. Log and JSON redaction is defense in depth; rotate a token immediately if exposure is
suspected.

H1Vault does not read browser cookies, browser profiles, or authenticated pages. It uses the
documented HackerOne Hacker API with HTTP Basic authentication and deliberately exposes only GET
and HEAD at its authenticated transport boundary.

## Untrusted attachments

Every report attachment is untrusted, even when its name or MIME type looks harmless. HackerOne
explicitly warns that attachments can contain dangerous proof-of-concept material. H1Vault saves
attachments as opaque bytes; it does not execute, import, preview, parse, or open them. Do not open
proof-of-concept files on a workstation. Analyze them only in a disposable, isolated sandbox with
network access disabled and no mounted credentials or private backups.

Downloads must use HTTPS, are streamed with a hard byte limit, and reject redirects to loopback,
link-local, private, unspecified, or otherwise non-public IP addresses. Paths are sanitized and
checked for traversal and symlink escapes. Temporary files are atomically replaced and removed on
failure.

## Backup confidentiality

Backups can contain confidential or undisclosed vulnerabilities, personal data, internal comments,
and executable exploit material. Store the output on encrypted local storage. Restrict directory
permissions to the account running H1Vault. Do not place backups in cloud-synchronized folders.
H1Vault itself has no telemetry, analytics, update checker, upload path, or third-party content
processor.

Temporary attachment capabilities (`expiring_url`) are redacted before JSON or Markdown is written.
Before sharing a ZIP, run `h1vault verify`, inspect the archive, and use a reputable secret scanner.
Share only with recipients authorized to access every included report. A successful H1Vault check
does not replace organizational disclosure rules or a full secret scan.

