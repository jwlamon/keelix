package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jwlamon/keelix/internal/engine"
	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// findMCPServer returns the probed server named "fake", or nil.
func findMCPServer(p *model.MCPProbe) *model.MCPServerProbe {
	if p == nil {
		return nil
	}
	for i := range p.Servers {
		if p.Servers[i].Name == "fake" {
			return &p.Servers[i]
		}
	}
	return nil
}

// TestProbeMCP_EndToEnd_InventoryThenDrift drives the full SP1b path: the
// engine derives a ServerSpec from a Signals fixture, runs mcpprobe.Probe
// through the REAL sandbox.NewRunner() on the host platform, and MCP007 then
// reports inventory (run 1) and Critical tool-poisoning drift (run 2).
func TestProbeMCP_EndToEnd_InventoryThenDrift(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("sandbox runner unsupported on %s; integration probe skipped", runtime.GOOS)
	}
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	// Pin the drift baseline into the temp HOME so ~/.keelix/mcp-baseline.json
	// is isolated and starts empty.
	t.Setenv("HOME", dir)
	if runtime.GOOS == "linux" {
		// child_linux Landlock denies $HOME by design; ensure the baseline dir
		// the PARENT writes still exists regardless.
		_ = os.MkdirAll(filepath.Join(dir, ".keelix"), 0o755)
	}

	run := func(desc string) *model.Result {
		t.Helper()
		sigPath := writeMCPSignalsFixture(t, dir, selfBin, desc)
		in := engine.Input{
			ComposePath: filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml"),
			Options: model.ScanOptions{
				NoProbe:         true,
				SignalsPath:     sigPath,
				MCPProbeEnabled: true,
				MCPProbeConsent: true, // non-interactive consent for the test
			},
		}
		r, err := engine.Scan(context.Background(), in)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		return r
	}

	// Run 1: first sight of the server => inventory, no drift.
	r1 := run("original description")
	srv := findMCPServer(r1.Collector.MCPProbe)
	if srv == nil {
		t.Fatalf("run 1: MCPProbe has no server named %q; probe did not run", "fake")
	}
	if !srv.Reached {
		t.Fatalf("run 1: server not reached; errors=%v", srv.Errors)
	}
	if srv.SandboxTier == "" {
		t.Errorf("run 1: SandboxTier empty; want a tier (tier0/landlock/bwrap/seatbelt)")
	}
	if len(srv.Tools) != 1 || srv.Tools[0].Name != "do_thing" {
		t.Fatalf("run 1: tools = %+v; want exactly one tool do_thing", srv.Tools)
	}
	if !srv.Tools[0].FirstSeen || srv.Tools[0].Drifted {
		t.Errorf("run 1: tool FirstSeen=%v Drifted=%v; want FirstSeen=true Drifted=false",
			srv.Tools[0].FirstSeen, srv.Tools[0].Drifted)
	}
	if hasFinding(r1, "MCP007", model.SeverityCritical) {
		t.Errorf("run 1: unexpected MCP007 Critical on first inventory")
	}

	// Run 2: same server identity, mutated tool description => drift => Critical.
	r2 := run("MALICIOUSLY CHANGED description")
	srv2 := findMCPServer(r2.Collector.MCPProbe)
	if srv2 == nil {
		t.Fatalf("run 2: MCPProbe has no server named %q", "fake")
	}
	if len(srv2.Tools) != 1 || !srv2.Tools[0].Drifted {
		t.Fatalf("run 2: tool drift = %+v; want Drifted=true", srv2.Tools)
	}
	if !hasFinding(r2, "MCP007", model.SeverityCritical) {
		t.Errorf("run 2: expected MCP007 Critical tool-poisoning drift finding")
	}
}
