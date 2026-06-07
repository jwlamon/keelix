# Keelix

> **Don't ship with a hole in the hull.**

Keelix is a local-first security scanner for self-hosted infrastructure. Run one command on your box and it grades the **whole machine** — host OS, Docker containers, the services you run, your network exposure, supply-chain CVEs (CISA KEV / FIRST EPSS), and the part nobody else checks: the **AI agents and MCP servers** running on the box.

It runs entirely on your machine. The values it reads (agent tokens, MCP secrets, configs) **never leave the box** — and because Keelix is open source, you can verify that yourself.

```
$ keelix scan

Keelix   Posture Score: 61/100  [YELLOW]

AI / MCP Posture
  AI agents:   sub-score 57/100 · 9 issue(s) · unattended autonomy
  MCP servers: sub-score 57/100 · 5 issue(s)

  🔴 CRITICAL  Agent auto-approval enabled                      [AGT001]
  🔴 CRITICAL  Plaintext secret in MCP server configuration     [MCP001]
  🔴 CRITICAL  Localhost HTTP/SSE MCP on vulnerable SDK version  [MCP005]
  ...
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/jwlamon/keelix/main/install.sh | sh
```

The installer downloads the right binary for your OS/arch, **verifies its SHA-256 checksum**, and drops it on your PATH. Or build from source:

```sh
go install github.com/jwlamon/keelix/cmd/keelix@latest
```

Supported: Linux and macOS (amd64 / arm64).

## Use it

```sh
keelix scan                          # whole-box posture of this machine
keelix scan -c docker-compose.yml    # also audit a Compose stack
keelix scan -c docker-compose.yml -H myserver.example.com   # + probe a host
keelix scan --report html -o report.html                    # shareable report
keelix collect                       # inspect the inside-out signals it gathers
```

`keelix scan` with no arguments auto-collects this box's inside-out signals and prints a single blended grade led by the AI/MCP posture. Nothing is sent anywhere. Add `--no-collect` to skip collection, `--json` for machine-readable output, `--ci` to exit non-zero on a critical.

## What it checks

| Domain | Examples |
|---|---|
| **AI agents** | auto-approval / unattended autonomy, the lethal-trifecta (private data + untrusted input + exfil), whole-disk filesystem scope |
| **MCP servers** | plaintext secrets, unverified provenance, vulnerable transports, tool-poisoning drift |
| **Host OS** | SSH exposure, accounts, patch posture, firewall policy, sysctl hardening |
| **Containers** | privileged/cap-heavy containers, docker.sock exposure, daemon TCP API, docker-group membership |
| **Services** | no-auth Redis/Mongo/PostgreSQL/Elasticsearch/MinIO, exposed Grafana/Jenkins/Vaultwarden/Traefik dashboards, and more |
| **Network** | what's *actually* reachable from outside (with `-H`), firewall-bypass, reverse-proxy and TLS posture |
| **Supply chain** | images affected by known-exploited (KEV) or high-EPSS CVEs — bundled offline, no scan-time network calls |

Findings map to SOC 2 / ISO 27001 / CIS controls. The deterministic checks are the core and never depend on AI for correctness; an optional Claude-powered layer (`--ai`, needs `ANTHROPIC_API_KEY`) only explains findings and drafts fixes.

## How scoring works

Each finding's risk is `impact × exposure × exploitability × confidence`, normalized over everything actually assessed, with hard caps for the worst cases (a known-exploited, internet-reachable service — or a lethal-trifecta agent — caps the box RED). AI/MCP risk is weighted at full strength regardless of network reachability: a misconfigured local agent is dangerous whether or not anything is listening on a port.

## Privacy

- **Zero telemetry.** Keelix collects no analytics and phones home for nothing.
- **`keelix scan` makes no outbound network calls.** It reads your box, scores it locally, and prints the result. The only network activity in the whole tool is opt-in: the outside-in probe (`-H`), AI enrichment (`--ai`, your key), and `keelix push` (you explicitly sending a result to Keelix Cloud).
- **Secrets are redacted at the collector boundary** — they never reach a finding, report, or `--json`.

It's open source precisely so you don't have to take our word for any of this.

## Keelix Cloud

The CLI is free and open source. For teams, **[Keelix Cloud](https://keelix.dev)** adds a hosted dashboard: fleet history, scheduled re-scans, alerts on new exposure, RBAC/SSO, and audit-ready posture reports. The CLI can push results to it (`keelix push`).

## License

[Apache 2.0](LICENSE).
