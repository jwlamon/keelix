//go:build darwin

package collect

import (
	"os/exec"

	"github.com/jwlamon/keelix/internal/model"
)

// collectPackages runs softwareupdate -l and delegates to the pure parser.
func collectPackages() (model.PackageState, error) {
	out, err := exec.Command("softwareupdate", "-l").Output()
	if err != nil {
		return model.PackageState{}, err
	}
	return parseSoftwareUpdate(out), nil
}
