package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// consentEnv is the pure input to the MCP-probe consent decision. The CLI fills
// it from the resolved ScanOptions, the planned probe commands, and whether
// stdin is a real terminal. Keeping it a value makes the decision unit-testable
// without a real TTY.
type consentEnv struct {
	enabled   bool     // Options.MCPProbeEnabled
	consented bool     // Options.MCPProbeConsent (--probe-mcp-yes)
	isTTY     bool     // stdin is an interactive terminal
	commands  []string // human-readable list of commands the probe will execute
}

// resolveMCPConsent decides whether the active MCP probe may run. It returns
// true ONLY when the operator has, or just gave, explicit consent.
//
//   - probe not enabled              -> true  (nothing to gate; caller skips probe anyway)
//   - already consented              -> true
//   - not a TTY (CI/--json/piped)    -> false + stderr refusal; NEVER auto-execute untrusted code
//   - TTY: print exact commands, prompt y/N (default No), proceed only on yes
//
// in is the prompt input stream (os.Stdin in production); out is the notice/prompt
// sink (os.Stderr in production).
func resolveMCPConsent(env consentEnv, in io.Reader, out io.Writer) bool {
	if !env.enabled {
		return true
	}
	if env.consented {
		return true
	}
	if !env.isTTY {
		fmt.Fprintln(out, "keelix: --probe-mcp requires explicit consent; refusing to execute untrusted MCP server code in a non-interactive session. Re-run with --probe-mcp-yes to consent. Continuing WITHOUT the active probe.")
		return false
	}
	fmt.Fprintln(out, "The active MCP probe will execute the following untrusted commands in a best-effort sandbox:")
	for _, c := range env.commands {
		fmt.Fprintf(out, "  - %s\n", c)
	}
	fmt.Fprint(out, "Proceed? [y/N] ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
