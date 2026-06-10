//go:build linux

package collect

import (
	"os"
	"os/exec"

	"github.com/jakelamon/keelix/internal/model"
)

// collectProcesses runs ps and delegates to the pure parser. On error it
// returns a nil slice and the error so Collect can record a CollectError.
// After parsing, it best-effort populates ProcessFact.Groups by reading
// /etc/passwd and /etc/group — required for HRD010 to fire.
func collectProcesses() ([]model.ProcessFact, error) {
	out, err := exec.Command("ps", "-eo", "pid,uid,comm,args").Output() // #nosec G204 -- fixed args, no user input
	if err != nil {
		return nil, err
	}
	procs := parseProcesses(out)

	// Best-effort: populate Groups from /etc/passwd + /etc/group.
	// Errors are silently ignored so a missing or unreadable file never
	// prevents the rest of the scan from running.
	passwdBytes, err1 := os.ReadFile("/etc/passwd") // #nosec G304 -- fixed well-known system path
	groupBytes, err2 := os.ReadFile("/etc/group")   // #nosec G304 -- fixed well-known system path
	if err1 == nil && err2 == nil {
		populateProcessGroupsFromFiles(procs, passwdBytes, groupBytes)
	}

	return procs, nil
}
