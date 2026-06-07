package collect

import (
	"strings"
	"time"
)

// eolTable is the bundled Debian/Ubuntu EOL-date table.
// Key: "<id>/<version_id>" (lower-cased). Value: EOL date (exclusive: on or
// after this date the distro is considered end-of-life).
// Source: Debian LTS schedule + Ubuntu release cadence (verified 2026-06-04).
var eolTable = map[string]time.Time{
	// Debian (LTS end dates)
	"debian/9":  time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC),
	"debian/10": time.Date(2024, 6, 30, 0, 0, 0, 0, time.UTC),
	"debian/11": time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC),
	"debian/12": time.Date(2028, 6, 10, 0, 0, 0, 0, time.UTC),

	// Ubuntu (standard 5y LTS end dates)
	"ubuntu/18.04": time.Date(2023, 4, 30, 0, 0, 0, 0, time.UTC),
	"ubuntu/20.04": time.Date(2025, 5, 31, 0, 0, 0, 0, time.UTC),
	"ubuntu/22.04": time.Date(2027, 4, 30, 0, 0, 0, 0, time.UTC),
	"ubuntu/24.04": time.Date(2029, 4, 30, 0, 0, 0, 0, time.UTC),
}

// parseOSRelease parses /etc/os-release and returns:
//
//	distro       — the ID field (e.g. "debian", "ubuntu"), lower-cased
//	version      — the VERSION_ID field (e.g. "12", "22.04")
//	eol          — true when the distro+version appears in eolTable AND
//	               collectedAt is on or after the EOL date
//
// The function is PURE: collectedAt is the only external input (injected
// from Signals.CollectedAt for deterministic testing).
func parseOSRelease(b []byte, collectedAt time.Time) (distro, version string, eol bool) {
	kvs := make(map[string]string)
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		// Strip optional surrounding quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		kvs[key] = val
	}

	distro = strings.ToLower(kvs["ID"])
	version = kvs["VERSION_ID"]

	tableKey := distro + "/" + version
	if eolDate, ok := eolTable[tableKey]; ok {
		eol = !collectedAt.Before(eolDate)
	}
	return distro, version, eol
}
