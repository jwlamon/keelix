//go:build linux

package collect

import (
	"os"
	"os/exec"
	"time"

	"github.com/jwlamon/keelix/internal/model"
)

// collectPackages reads apt upgradable state plus side-channel facts
// (reboot-required flag file, distro EOL via /etc/os-release) and
// delegates to the pure parsers.
func collectPackages() (model.PackageState, error) {
	out, err := exec.Command("apt", "list", "--upgradable").Output()
	if err != nil {
		return model.PackageState{}, err
	}
	_, rebootErr := os.Stat("/var/run/reboot-required")
	rebootRequired := rebootErr == nil

	// Determine DistroEOL from /etc/os-release.
	distroEOL := false
	if b, err := os.ReadFile("/etc/os-release"); err == nil { // #nosec G304 -- fixed path
		_, _, distroEOL = parseOSRelease(b, time.Now().UTC())
	}

	return parseAptState(out, rebootRequired, distroEOL), nil
}
