//go:build linux

package collect

import (
	"os/exec"

	"github.com/jwlamon/keelix/internal/model"
)

// collectSockets shells out to `ss -tlnpH` and delegates ALL parsing to the
// pure parseSS. Thin exec wrapper: the only logic here is running the command.
func collectSockets(Options) ([]model.ListeningSocket, error) {
	out, err := exec.Command("ss", "-tlnpH").Output() // #nosec G204 -- fixed args, no user input
	if err != nil {
		return nil, err
	}
	return parseSS(out), nil
}
