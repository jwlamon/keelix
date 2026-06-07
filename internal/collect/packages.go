package collect

import (
	"strings"

	"github.com/jwlamon/keelix/internal/model"
)

// parseAptState counts pending security upgrades from `apt list --upgradable`
// output. A line is a security update when its source pocket contains
// "-security". rebootRequired and distroEOL are gathered by the wrapper
// (presence of /var/run/reboot-required and distro support status) and threaded
// through so this stays a pure function.
func parseAptState(b []byte, rebootRequired, distroEOL bool) model.PackageState {
	var sec int
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		// Format: name/pocket version arch [upgradable from: ...]
		slash := strings.IndexByte(line, '/')
		sp := strings.IndexByte(line, ' ')
		if slash < 0 || sp < 0 || slash > sp {
			continue
		}
		pocket := line[slash+1 : sp]
		if strings.Contains(pocket, "-security") {
			sec++
		}
	}
	return model.PackageState{
		Manager:                "apt",
		SecurityUpdatesPending: sec,
		RebootRequired:         rebootRequired,
		DistroEOL:              distroEOL,
	}
}

// parseSoftwareUpdate counts pending updates from `softwareupdate -l` output and
// flags RebootRequired when any label declares a restart action.
func parseSoftwareUpdate(b []byte) model.PackageState {
	var pending int
	var reboot bool
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "* Label:") {
			pending++
		}
		if strings.Contains(line, "Action: restart") {
			reboot = true
		}
	}
	return model.PackageState{
		Manager:                "softwareupdate",
		SecurityUpdatesPending: pending,
		RebootRequired:         reboot,
	}
}
