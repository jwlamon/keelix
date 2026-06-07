package engine

import (
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestPlannedMCPProbeCommands(t *testing.T) {
	in := Input{}
	// PlannedMCPProbeCommands reads from a pre-collected SignalsPath OR from the
	// already-built signals; here we exercise the pure formatter directly.
	specs := deriveServerSpecs(sig(map[string]string{
		"mcpServers.alpha.command": "npx",
		"mcpServers.alpha.args.0":  "@scope/server",
		"mcpServers.remote.type":   "http",
		"mcpServers.remote.url":    "https://mcp.example.com/rpc",
	}))
	cmds := formatPlannedCommands(specs)
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "npx @scope/server") {
		t.Errorf("stdio command not rendered: %q", joined)
	}
	if !strings.Contains(joined, "https://mcp.example.com/rpc") {
		t.Errorf("http target not rendered: %q", joined)
	}
	_ = in
}

func TestScanSkipsProbeWithoutConsent(t *testing.T) {
	// Probe must not run (sig.MCPProbe stays nil) unless Enabled && Consent.
	sigIn := &model.Signals{}
	out, _ := maybeProbeMCP(model.ScanOptions{MCPProbeEnabled: true, MCPProbeConsent: false}, sigIn, t.TempDir()+"/baseline.json")
	if out != nil {
		t.Fatal("probe ran without consent")
	}
	out, _ = maybeProbeMCP(model.ScanOptions{MCPProbeEnabled: false, MCPProbeConsent: true}, sigIn, t.TempDir()+"/baseline.json")
	if out != nil {
		t.Fatal("probe ran without --probe-mcp")
	}
}
