package collect

import (
	"strings"
)

// parseAptPeriodic parses /etc/apt/apt.conf.d/20auto-upgrades (and similar
// files) to determine whether unattended security upgrades are enabled.
//
// The APT conf format uses:
//
//	APT::Periodic::<Key> "<value>";
//
// Values emitted:
//
//	update_package_lists  — value of APT::Periodic::Update-Package-Lists
//	unattended_upgrade    — value of APT::Periodic::Unattended-Upgrade
//
// The schemaID is "apt-periodic"; known is true when at least one relevant
// key is found. Lines beginning with "//" are APT-style comments and skipped.
func parseAptPeriodic(b []byte) (map[string]string, string, bool) {
	vals := make(map[string]string)
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove trailing semicolon.
		line = strings.TrimSuffix(line, ";")
		line = strings.TrimSpace(line)

		var key, val string
		switch {
		case strings.HasPrefix(line, `APT::Periodic::Update-Package-Lists`):
			key = "update_package_lists"
		case strings.HasPrefix(line, `APT::Periodic::Unattended-Upgrade`):
			key = "unattended_upgrade"
		default:
			continue
		}

		// Extract the quoted value: APT::Periodic::Key "value"
		q1 := strings.IndexByte(line, '"')
		q2 := strings.LastIndexByte(line, '"')
		if q1 >= 0 && q2 > q1 {
			val = line[q1+1 : q2]
		}
		vals[key] = val
	}
	if len(vals) == 0 {
		return nil, "", false
	}
	return vals, "apt-periodic", true
}
