package sandbox

import (
	"os"
	"testing"
)

// TestMain makes the sandbox test binary act as its own re-exec trampoline.
//
// Several Linux tests (and the linuxRunner itself) verify isolation by
// re-execing THIS binary as `__mcp-sandbox-child <tempDir> <homeDir> <cacheCSV>
// -- <realcmd...>`. The trampoline child must apply Landlock + rlimits and then
// syscall.Exec the real command IN PLACE — it must NOT boot the Go test
// framework, because doing so would (a) run the whole suite inside the
// restricted child and (b) risk other tests applying sticky restrictions in
// that child process. Dispatching here, BEFORE m.Run(), guarantees the child is
// a pure trampoline.
//
// RunSandboxChild syscall.Exec's the inner command and never returns on success;
// on non-Linux platforms it is a no-op stub, so this branch is inert off Linux
// and the darwin test run is unaffected.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__mcp-sandbox-child" {
		os.Exit(RunSandboxChild(os.Args[2:]))
	}
	// __landlock-probe is the inner command the trampoline exec's into so the
	// Landlock filesystem/network guarantees can be asserted from a SUBPROCESS
	// (never in the test process, which Landlock would corrupt). On non-Linux
	// platforms runLandlockProbe is absent so this branch is compiled out via
	// the linux build tag on landlock_probe_linux_test.go; the arg never appears
	// off Linux.
	if len(os.Args) > 1 && os.Args[1] == "__landlock-probe" {
		os.Exit(runLandlockProbe(os.Args[2:]))
	}
	os.Exit(m.Run())
}
