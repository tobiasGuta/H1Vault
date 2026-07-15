# Changelog

All notable H1Vault changes are documented here.

## 0.2.0 - 2026-07-15

- Added SQLite schema 2 and evidence-preserving historical attachment reconciliation.
- Kept valid archived attachments downloaded when later refreshes use `--skip-attachments`.
- Prevented link-based pagination from falling back to numbered pages after `links.next` ends.
- Preserved complete detailed-report JSON:API documents, including top-level additions.
- Added verification and snapshot coverage for historical attachment versions.

## 0.1.0 — 2026-07-14

- Initial open-source release.
- Added read-only HackerOne Hacker API report discovery and exact program filtering.
- Added Markdown/JSON export, safe attachment downloads, incremental SQLite state,
  integrity verification, portable snapshots, OS-keyring credentials, and CLI diagnostics.
- Split evidence-preserving raw/original exports from explicitly sanitized presentation exports.
- Added schema-2 per-file hashes/sizes, strict untracked-file verification, and manifest-only ZIPs.
- Disabled ambient HTTP proxy/CA configuration and pinned attachment connections to validated DNS IPs.
- Added Windows/Ubuntu Python 3.12/3.13 CI, coverage, pip-audit, and CodeQL workflows.
