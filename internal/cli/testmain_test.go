package cli

import (
	"os"
	"testing"

	"github.com/jakelamon/keelix/internal/sandbox"
)

// TestMain makes the cli test binary act as its own Linux sandbox trampoline.
//
// On Linux the real runner (sandbox.NewRunner -> linuxRunner) probes a stdio
// MCP server by re-execing THIS test binary as
// `__mcp-sandbox-child <tempDir> <homeDir> <cacheCSV> -- <realcmd...>`. The
// trampoline child applies Landlock + rlimits and then syscall.Exec's the real
// command (here: the test binary re-run as `-test.run TestCLIHelperMCPServer`
// with KEELIX_TEST_MCP_SERVER=1, i.e. the fake MCP server). In the production
// keelix binary that dispatch lives in the hidden `__mcp-sandbox-child` cobra
// command; the test binary has no cobra root, so we must dispatch it here.
//
// sandbox.RunSandboxChild syscall.Exec's the inner command and never returns on
// success; on non-Linux platforms it is a no-op stub, so this branch is inert
// off Linux. Without this dispatch the trampoline child would do nothing and the
// active MCP probe would read EOF on the initialize handshake.
//
// os.Exit from TestMain is explicitly permitted by the testing package.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__mcp-sandbox-child" {
		os.Exit(sandbox.RunSandboxChild(os.Args[2:]))
	}
	os.Exit(m.Run())
}
