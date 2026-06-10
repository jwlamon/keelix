//go:build darwin

package collect

import (
	"os/exec"

	"github.com/jakelamon/keelix/internal/model"
)

// collectProcesses runs ps and delegates to the pure parser. On error it
// returns a nil slice and the error so Collect can record a CollectError.
func collectProcesses() ([]model.ProcessFact, error) {
	out, err := exec.Command("ps", "-axo", "pid,uid,comm,args").Output()
	if err != nil {
		return nil, err
	}
	return parseProcesses(out), nil
}
