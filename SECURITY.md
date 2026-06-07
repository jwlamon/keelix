# Security Policy

## Reporting a vulnerability

Please report security issues privately — **do not** open a public issue for a
vulnerability.

- Preferred: open a [private security advisory](https://github.com/jwlamon/keelix/security/advisories/new) on this repo.
- Or email **info@keelix.dev** with details and, if possible, a reproduction.

We aim to acknowledge reports within 3 business days and to ship a fix or
mitigation as quickly as the severity warrants. We'll credit reporters who want
it once a fix is released.

## Scope

Keelix is a local scanner that reads sensitive files on the machine it runs on
(agent configs, MCP server definitions, host config). Two properties matter most:

- **`keelix scan` makes no outbound network calls.** Collected values never
  leave the box. The only commands that talk to the network are the opt-in
  outside-in probe (`-H`), the optional AI enrichment (`--ai`, your API key),
  and `keelix push` (explicitly sending a result to Keelix Cloud). You can
  verify this in the source.
- **Secret values are redacted at the collector boundary** before they reach any
  finding, report, or `--json` output. A reported "plaintext secret" finding
  shows a `[secret]` marker, not the value.

Issues we especially want to hear about: a code path where `keelix scan` sends
data off the box; a way to make the collector read outside its allowlist or
follow a symlink out of bounds; a redaction bypass that leaks a real secret into
output; or sandbox-escape in the consent-gated MCP probe (`--probe-mcp`).

## Supported versions

Keelix is pre-1.0; security fixes land on `main` and in the latest tagged
release. Please test against the latest release before reporting.

## Installer integrity

The `curl … | sh` installer verifies the binary's SHA-256 against the release
`checksums.txt` and fails closed if it can't (override with `KEELIX_SKIP_VERIFY=1`
at your own risk). You can always download the binary and checksum manually from
the [releases page](https://github.com/jwlamon/keelix/releases), or build from
source with `go install github.com/jwlamon/keelix/cmd/keelix@latest`.
