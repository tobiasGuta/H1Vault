# H1Vault

H1Vault is a local, read-only command-line archive for reports that a HackerOne security researcher
personally submitted and can access. It retrieves the researcher's own report history, filters it by
an exact program handle, and produces readable Markdown, normalized JSON, attachment hashes,
incremental state, integrity checks, and portable snapshots.

H1Vault is not a program-management client and is not a way to enumerate other researchers' reports.

## Read-only safety guarantee

The authenticated HackerOne client supports only HTTP `GET` and `HEAD`. It cannot submit or edit a
report, comment, bounty, disclosure request, state, or program setting. It never guesses adjacent
report IDs, scrapes HackerOne pages, or reads browser cookies. Network traffic is limited to the
official HackerOne API and temporary HTTPS attachment hosts returned in an accessible report.
There is no telemetry, analytics, crash upload, cloud synchronization, or automatic update check.

## Requirements and supported systems

- Python 3.12 or newer
- Windows 11, current Linux distributions, or macOS
- A personal HackerOne API token
- An OS keyring backend for persistent `auth set` storage (optional when using environment values)

## Installation

From the project directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
h1vault --help
python -m h1vault --help
```

On Linux or macOS, activate with `source .venv/bin/activate`.

## Create a personal API token

Sign in to HackerOne, open the **API Token** page in account settings, and generate a personal API
token. Generation revokes the previous personal token and the new token is shown only once. The API
token identifier is the Basic-auth username; it is not necessarily the normal HackerOne username.
Follow the current [official API-token instructions](https://docs.hackerone.com/en/articles/8410331-api-token).

Never put a real token in source code, a committed `.env`, a command-line argument, or a shell script.

## Configure credentials on Windows

Temporary PowerShell environment values override the keyring:

```powershell
$env:H1_API_USERNAME="your-api-token-identifier"
$env:H1_API_TOKEN="your-api-token-value"
```

For persistent OS-keyring storage, enter both values through secure prompts:

```powershell
h1vault auth set
h1vault auth status
```

`auth clear` removes only keyring entries and never changes environment variables. The token prompt
is hidden and no command accepts credential flags.

## Quick start

```powershell
h1vault doctor

h1vault programs list

h1vault sync `
  --program "example-program" `
  --output "D:\HackerOneBackups"

h1vault verify `
  --program "example-program" `
  --output "D:\HackerOneBackups"
```

Use `programs list --json` for a machine-readable list of programs represented in your own report
history. This is not a list of every HackerOne program.

## Report listing and single-report export

```powershell
h1vault reports list --program "example-program"
h1vault reports list --state triaged --severity high --limit 25 --json
h1vault report export 123456 --output "D:\HackerOneBackups"
```

Single-report export requests exactly the supplied ID and works only when the authenticated account
can access it. A 403 or 404 stops that request; H1Vault never probes nearby IDs.

## Incremental synchronization

H1Vault first paginates every report returned by `GET /hackers/me/reports`, using pages of 100, then
performs normalized exact program-handle filtering locally. It requests detail only for new, changed,
failed, missing, or explicitly refreshed reports. Attachment IDs, sizes, paths, hashes, and status are
tracked in SQLite. A second unchanged run avoids rewriting report exports and avoids attachment
downloads. Existing attachments are SHA-256 checked before reuse.

When a later API response no longer contains an archived attachment, H1Vault preserves its local
bytes and SHA-256, marks the record `historical`, and labels it as absent from the latest response in
both `metadata.json` and the manifest. Filename, size, or source-location changes preserve the prior
version before archiving the current one. `--skip-attachments` prevents new downloads; it does not
invalidate an already downloaded attachment that still passes its integrity and metadata checks.

```powershell
h1vault sync --program "example-program" --output "D:\HackerOneBackups" --dry-run
h1vault sync --program "example-program" --output "D:\HackerOneBackups" --refresh
h1vault sync --program "example-program" --output "D:\HackerOneBackups" --skip-attachments
h1vault sync --program "example-program" --output "D:\HackerOneBackups" --max-attachment-size-mb 256
```

Attachments are included by default with a 1,024 MiB per-file maximum. Processing continues after a
report-level failure unless `--fail-fast` is supplied. `--dry-run` lists the intended classification
without creating directories, updating SQLite, writing files, or downloading attachments.

## Attachment safety warning

**Treat every downloaded attachment as hostile proof-of-concept material.** H1Vault stores bytes but
never opens, executes, imports, parses, or previews them. Names and MIME types are not evidence of
safety. Use an isolated disposable analysis environment, not the workstation holding credentials and
private reports. See [SECURITY.md](SECURITY.md).

Downloads are streamed, byte-limited, hashed, and atomically finalized. Redirects are bounded and
revalidated; local/private network destinations and non-HTTPS URLs are rejected. Expired URLs are
refreshed from the same exact report once. Temporary URLs are never persisted.

## Backup structure

```text
HackerOneBackups/
└── example-program/
    ├── index.md
    ├── index.json
    ├── manifest.json
    ├── program.json
    ├── state.sqlite3
    └── reports/
        └── 123456-example-title/
            ├── report.md
            ├── report.raw.json
            ├── report.sanitized.json
            ├── original-report.md
            ├── timeline.json
            ├── metadata.json
            └── attachments/
```

The report ID is the stable directory identity; the title suffix is cosmetic. Remote filenames are
made Windows-safe, length-limited, collision-resistant through attachment IDs, and contained beneath
the expected attachment directory.

`report.raw.json` preserves the complete accessible JSON:API response document, including top-level
`included`, `meta`, and `links` additions, replacing only API-generated temporary attachment
capabilities. `original-report.md` preserves the researcher's vulnerability
information and separate impact text without sanitizing PoC headers or signed-example parameters.
These two files are confidential and are not safe-to-share views. `report.sanitized.json`,
`timeline.json`, and the clearly labeled `report.md` apply defensive redaction for presentation.

Backups created by H1Vault before manifest schema 2 must be synchronized once before `verify` or
`snapshot`. The next sync detects the missing split exports, regenerates them, removes legacy
`report.json`, atomically writes the schema-2 manifest, and migrates SQLite attachment state to
schema 2 so historical provenance can be retained.

## Verification

`h1vault verify --program HANDLE --output PATH` returns nonzero for a malformed manifest, missing or
invalid report files, modified report or attachment hashes/sizes, report identity or program
disagreement, metadata/manifest disagreement, unexpected report directories, untracked files,
links/reparse points, stale partial files, unsafe paths, SQLite disagreement, temporary capabilities,
or secrets leaked into generated sanitized files. Evidence-preserving raw/original files may contain
PoC credentials exactly as submitted and must be handled as confidential. Verification does not
execute attachments.

## Portable ZIP snapshots

```powershell
h1vault snapshot `
  --program "example-program" `
  --output "D:\HackerOneBackups" `
  --destination "E:\Archives\example-program.zip"
```

H1Vault warns that the archive is confidential and verifies the backup first. It refuses on failure
unless `--force` is supplied; unsafe links, reparse points, and untracked files are refused even with
force. ZIPs use the manifest's explicit file allowlist rather than walking the directory. Every source
is opened without following links, hashed on the same file descriptor, and streamed from that exact
handle. ZIPs exclude `state.sqlite3`, logs, and temporary files and include the human-readable
manifest. Store and share them as sensitive security data.

## Configuration

H1Vault reads `config.toml` from the platform application-config directory (for example,
`%LOCALAPPDATA%\h1vault\config.toml` on Windows):

```toml
[api]
page_size = 100
max_retries = 4
concurrency = 3

[backup]
default_output = "D:/HackerOneBackups"
include_attachments = true
max_attachment_size_mb = 1024

[logging]
level = "INFO"
```

Precedence is CLI, supported `H1VAULT_*` environment settings, configuration file, then safe
defaults. TLS verification cannot be disabled and the production CLI cannot change the API base.
Global `--verbose`, `--quiet`, and `--log-file PATH` options control redacted logging.

## Rate limits and network behavior

H1Vault uses one bounded HTTPX client with verified TLS, explicit connect/read/write/pool timeouts,
three connections, and a descriptive user agent. Only idempotent requests are retried: connection
failures, timeouts, 429, 500, 502, 503, and 504. Backoff is exponential with jitter and honors
`Retry-After`. Clear client errors such as 400, 401, 403, and 404 are not retried.

## Troubleshooting

- **Missing credentials:** set both environment values or run `h1vault auth set`.
- **401:** generate and configure a valid personal API token; generation revokes the old token.
- **403/404:** confirm the authenticated researcher can access that exact report.
- **No matching program:** run `h1vault programs list` and use the displayed exact handle.
- **Keyring unavailable:** install/configure a supported OS keyring, or use session environment values.
- **TLS/network timeout:** check system time, trusted roots, firewall, and VPN policy. H1Vault disables
  HTTPX environment trust, so `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `SSL_CERT_FILE`, and similar
  ambient proxy/certificate variables are not used. H1Vault has no implicit Burp/system-proxy mode
  and will not disable TLS verification.
- **429:** wait; H1Vault already honors the server delay and performs bounded automatic retries.
- **Unwritable output:** choose a local path for which the current account has create/write access.
- **Corrupt backup:** preserve it, run `verify --json`, then sync again to repair missing local files.

## Credential rotation and uninstallation

Generate a replacement token in HackerOne, then update the environment pair or run `h1vault auth set`
again. Clear persistent values with `h1vault auth clear`. To uninstall:

```powershell
h1vault auth clear
python -m pip uninstall h1vault
```

Uninstallation intentionally does not delete backups. Remove them manually only after confirming
retention and disclosure requirements.

## Development and testing

```powershell
python -m pip install -e ".[dev]"
ruff format .
ruff check .
mypy src
pytest
```

Tests use HTTPX mock transports/Respx and never contact the real HackerOne API. Do not use a real
token in tests.

GitHub Actions runs formatting, linting, strict mypy, and coverage-enforced tests on Ubuntu and
Windows with Python 3.12 and 3.13. Separate jobs run `pip-audit` and CodeQL. Workflow presence does
not prove a run succeeded until the repository is pushed and GitHub reports a successful check.

## Exit codes

- `0`: requested operation completed successfully
- `1`: expected operational, authentication, API, synchronization, or integrity failure
- `2`: invalid CLI usage or invalid configuration
- `130`: keyboard interruption (provided by the command runtime)

## Limitations

H1Vault can preserve only data visible through the authenticated Hacker API response. Missing or
permission-restricted fields cannot be reconstructed. API additions are preserved where safe but may
not immediately gain specialized Markdown formatting. H1Vault does not decrypt, inspect, malware-scan,
or determine the safety of attachments. It does not upload, cloud-sync, or provide remote restoration.

## Privacy model

Report contents remain under the chosen local output root. Authentication goes only to
`https://api.hackerone.com/v1`; attachment requests go only to HTTPS capabilities returned by an
accessible report and use a separate client with no HackerOne Authorization header. Both clients
ignore ambient proxy and custom-certificate environment variables. Attachment DNS answers are
validated and the transport connects to the same pinned public IP while retaining hostname TLS
verification, closing the DNS-rebinding gap. Temporary attachment capabilities are removed from all
exports. Sanitized exports redact cookies, Authorization fields, and token-like values; raw/original
evidence intentionally preserves researcher-authored text. Logs do not contain full response bodies
by default. Review filesystem permissions and all archive recipients.

H1Vault uses the [official Hacker API documentation](https://api.hackerone.com/hacker-resources/) as
its protocol source. HackerOne may add fields without a version bump, so local models allow unknown
fields and treat optional relationships as nullable.
