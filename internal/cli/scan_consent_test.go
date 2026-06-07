package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/engine"
	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

func TestApplyMCPConsent_NonTTYDisablesConsent(t *testing.T) {
	var out bytes.Buffer
	in := engine.Input{}
	in.Options.MCPProbeEnabled = true
	in.Options.MCPProbeConsent = false
	applyMCPConsentWith(&in, false /*isTTY*/, []string{"npx evil"}, strings.NewReader("y\n"), &out)
	if in.Options.MCPProbeConsent {
		t.Fatal("non-TTY must leave MCPProbeConsent false")
	}
	if !strings.Contains(out.String(), "refusing") {
		t.Errorf("expected refusal notice, got %q", out.String())
	}
}

func TestApplyMCPConsent_TTYYesSetsConsent(t *testing.T) {
	var out bytes.Buffer
	in := engine.Input{}
	in.Options.MCPProbeEnabled = true
	in.Options.MCPProbeConsent = false
	applyMCPConsentWith(&in, true /*isTTY*/, []string{"npx server-a"}, strings.NewReader("y\n"), &out)
	if !in.Options.MCPProbeConsent {
		t.Fatal("TTY + yes must set MCPProbeConsent true")
	}
}

// TestScan_JSONFlagForcesNonInteractiveConsentGate verifies spec §5.3: when
// --json is present (machine-readable / non-interactive mode), the consent gate
// must REFUSE to run --probe-mcp unless --probe-mcp-yes was also supplied,
// regardless of whether stdin is a TTY. This is the integration path through
// the real newScanCmd.
func TestScan_JSONFlagForcesNonInteractiveConsentGate(t *testing.T) {
	// Write a minimal compose file.
	compose := filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml")

	// Write a signals file with a stdio MCP server so the engine has something
	// to probe if the gate were to pass.
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	sigPath := writeCLIMCPSignals(t, t.TempDir(), selfBin)

	dir := t.TempDir()
	outFile := filepath.Join(dir, "result.json")

	cmd := newScanCmd()
	// --json without --probe-mcp-yes: gate must refuse the probe.
	cmd.SetArgs([]string{
		"--json", "-o", outFile,
		"-c", compose,
		"--no-probe", "--signals", sigPath,
		"--probe-mcp", // NO --probe-mcp-yes
	})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var r model.Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	// The probe must NOT have run: MCPProbe must be nil.
	if r.Collector != nil && r.Collector.MCPProbe != nil {
		t.Fatalf("--json without --probe-mcp-yes must NOT run the probe (spec §5.3), got MCPProbe=%+v", r.Collector.MCPProbe)
	}
	// The refusal notice must have been emitted to stderr.
	if !strings.Contains(stderr.String(), "refusing") {
		t.Errorf("expected refusal notice on stderr, got %q", stderr.String())
	}
}
