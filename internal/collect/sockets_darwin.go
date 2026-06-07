//go:build darwin

package collect

import (
	"os/exec"

	"github.com/jwlamon/keelix/internal/model"
)

// collectSockets shells out to `lsof -nP -iTCP -sTCP:LISTEN` and delegates ALL
// parsing to the pure parseLsof. Thin exec wrapper only.
func collectSockets(Options) ([]model.ListeningSocket, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN").Output() // #nosec G204 -- fixed args, no user input
	if err != nil {
		return nil, err
	}
	return parseLsof(out), nil
}
