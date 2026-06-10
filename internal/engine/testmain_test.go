package engine_test

import (
	"os"
	"testing"

	"github.com/jakelamon/keelix/internal/sandbox"
)

// TestMain has two interception points that MUST be checked in this order
// before the test framework hands off to individual test goroutines:
//
//  1. The Linux sandbox trampoline. On Linux the real runner
//     (sandbox.NewRunner -> linuxRunner) re-execs THIS test binary as
//     `__mcp-sandbox-child -- <realcmd...>` so the child can apply Landlock +
//     rlimits and then exec the real command IN PLACE. In a normal (non-test)
//     keelix binary that dispatch lives in the hidden cobra command; the test
//     binary has no cobra root, so we must dispatch it here ourselves.
//     sandbox.RunSandboxChild syscall.Exec's the inner command and never
//     returns on success; on non-Linux it is a no-op stub. Without this branch
//     the trampoline child would do nothing and the probe reads EOF.
//
//  2. The helper-MCP-server entry point. When KEELIX_TEST_MCP_SERVER=1 is set
//     the binary is being used as a fake stdio MCP subprocess (the inner command
//     the trampoline exec's into) — run the server and exit immediately.
//
// os.Exit from TestMain is explicitly permitted by the testing package (unlike
// os.Exit from inside a tRunner goroutine, which panics on Go 1.24+).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__mcp-sandbox-child" {
		os.Exit(sandbox.RunSandboxChild(os.Args[2:]))
	}
	if os.Getenv("KEELIX_TEST_MCP_SERVER") == "1" {
		runHelperMCPServer()
		os.Exit(0)
	}
	os.Exit(m.Run())
}
