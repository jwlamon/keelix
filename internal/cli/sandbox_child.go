package cli

import (
	"os"

	"github.com/jwlamon/keelix/internal/sandbox"
	"github.com/spf13/cobra"
)

// newSandboxChildCmd builds the HIDDEN re-exec trampoline command. It is never
// user-facing: runner_linux.go invokes `keelix __mcp-sandbox-child -- ...` to
// self-restrict before exec'ing an untrusted MCP server. On non-linux builds
// sandbox.RunSandboxChild is a no-op stub.
func newSandboxChildCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "__mcp-sandbox-child",
		Hidden:             true,
		DisableFlagParsing: true, // pass the real command's flags through untouched
		Run: func(_ *cobra.Command, args []string) {
			os.Exit(sandbox.RunSandboxChild(args))
		},
	}
}
