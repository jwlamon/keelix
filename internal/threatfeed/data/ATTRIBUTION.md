# Threat-feed data attribution

`threatfeed.bin.gz` is a compact, offline snapshot of two public threat-intelligence
sources, regenerated at release time by `internal/threatfeed/gen`. It bundles only
exploitability metadata (whether a CVE is known-exploited, and its EPSS percentile) —
no host data ever leaves the machine.

**Snapshot date:** 2026-06-05 (see `internal/threatfeed/snapshot.go`).

## Sources

- **CISA Known Exploited Vulnerabilities (KEV) Catalog**
  Source: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
  License: U.S. Government work / public domain (CC0). No restrictions on reuse.
  Used for: the KEV flag (a known-exploited CVE drives the "patch now" signal and,
  at a routable exposure, caps the box RED).

- **FIRST.org Exploit Prediction Scoring System (EPSS)**
  Source: <https://www.first.org/epss> (data: <https://epss.empiricalsecurity.com>)
  Terms: EPSS scores are freely available for public use; attribution is requested.
  Attribution: *"Exploit Prediction Scoring System (EPSS) by the EPSS SIG, a Special
  Interest Group of FIRST.org."*
  Used for: the EPSS percentile (a high-percentile non-KEV CVE is a "patch soon" nudge).

Only the percentile column of EPSS is retained (quantized to one byte); the raw
probability is dropped. We bundle a daily snapshot rather than querying at scan time
so scans are deterministic and require no network access.

> **GA note:** confirm EPSS redistribution terms with FIRST.org before General
> Availability (tracked in the SP4 design spec §6). KEV (CC0) carries no such caveat.
