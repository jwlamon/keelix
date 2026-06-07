// Package threatfeed provides an offline, embedded snapshot of CISA KEV
// (known-exploited CVEs) and FIRST.org EPSS (exploit-prediction percentiles),
// and the lookup API the score engine uses to weight findings by real-world
// exploitability. All lookups are pure and deterministic: no network I/O, and
// no time-of-day dependence beyond the caller-injected `now` in IsStale.
package threatfeed

import (
	"strconv"
	"strings"
)

// parseCVE splits a canonical "CVE-YYYY-NNNNN" id into its numeric (year, seq)
// key. ok is false for empty or malformed ids (callers fail safe). The match is
// case-insensitive on the "CVE-" prefix. Year must be 4 digits; seq is 1+ digits.
//
// This MUST stay byte-for-byte equivalent to the generator's parseCVEKey
// (internal/threatfeed/gen/build.go) so the embedded keys and the lookup keys
// agree; both are deliberately tiny and identical.
func parseCVE(cve string) (year uint16, seq uint32, ok bool) {
	cve = strings.TrimSpace(cve)
	if len(cve) < len("CVE-YYYY-N") {
		return 0, 0, false
	}
	if !strings.EqualFold(cve[:4], "CVE-") {
		return 0, 0, false
	}
	rest := cve[4:]
	dash := strings.IndexByte(rest, '-')
	if dash != 4 { // year must be exactly 4 digits before the dash
		return 0, 0, false
	}
	sStr := rest[dash+1:]
	if sStr == "" {
		return 0, 0, false
	}
	y, err := strconv.ParseUint(rest[:dash], 10, 16)
	if err != nil {
		return 0, 0, false
	}
	s, err := strconv.ParseUint(sStr, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint16(y), uint32(s), true
}
