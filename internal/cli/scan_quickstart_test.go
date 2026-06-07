package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// TestScan_Quickstart_PanelPresent verifies that a scan's rendered output
// (markdown report) always contains the "AI / MCP Posture" section header,
// regardless of whether AI agents or MCP servers are detected.
//
// The test uses a compose + --no-probe --report md path so that it runs in a
// deterministic, network-free manner. This exercises the render-only panel
// introduced by the whole-box quickstart feature; the panel must appear whether
// or not collection found any signals (collection disabled here via default
// compose-mode: no --collect flag, so effectiveCollect=false).
func TestScan_Quickstart_PanelPresent(t *testing.T) {
	compose := filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml")

	dir := t.TempDir()
	outFile := filepath.Join(dir, "report.md")

	cmd := newScanCmd()
	cmd.SetArgs([]string{
		"-c", compose,
		"--no-probe",
		"--report", "md",
		"-o", outFile,
	})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("quickstart scan failed: %v\nstderr: %s", err, stderr.String())
	}

	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading report output: %v", err)
	}
	content := string(b)
	if !strings.Contains(content, "AI / MCP Posture") {
		t.Errorf("report does not contain 'AI / MCP Posture' panel header\nfull output:\n%s", content)
	}
}

// TestScan_Quickstart_TerminalPanelPresent verifies the terminal render path
// also contains the "AI / MCP Posture" header. This exercises report.Terminal
// which leads with the aiMcpPanel block.
//
// Signals are provided as a pre-collected minimal JSON (no AI agents, no MCP
// servers) so the panel takes the "none detected" honest path — not a false clean
// pass or a skip.
func TestScan_Quickstart_TerminalPanelPresent(t *testing.T) {
	compose := filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml")

	// Write a minimal but valid signals JSON that has no AI agents and no MCP
	// servers, exercising the "none detected" panel path honestly.
	dir := t.TempDir()
	sigPath := filepath.Join(dir, "signals.json")
	minimalSignals := `{"version":"1.0.0","collected_at":"2026-06-06T00:00:00Z","platform":{"os":"linux"},"privilege":{"root":false,"euid":1000},"packages":{},"firewall":{}}`
	if err := os.WriteFile(sigPath, []byte(minimalSignals), 0o600); err != nil {
		t.Fatalf("writing signals fixture: %v", err)
	}

	outFile := filepath.Join(dir, "report.md")
	cmd := newScanCmd()
	cmd.SetArgs([]string{
		"-c", compose,
		"--signals", sigPath,
		"--no-probe",
		"--report", "md",
		"-o", outFile,
	})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan with signals failed: %v\nstderr: %s", err, stderr.String())
	}

	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading report output: %v", err)
	}
	content := string(b)
	if !strings.Contains(content, "AI / MCP Posture") {
		t.Errorf("report does not contain 'AI / MCP Posture' panel header\nfull output:\n%s", content)
	}
}

// TestScan_JSONShape_Regression verifies that the --json output payload shape
// is unchanged by the whole-box quickstart feature: the keys score, rating,
// counts, and findings must always be present, and the panel (render-only) must
// NOT appear in the JSON payload.
func TestScan_JSONShape_Regression(t *testing.T) {
	compose := filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml")

	dir := t.TempDir()
	outFile := filepath.Join(dir, "result.json")

	cmd := newScanCmd()
	cmd.SetArgs([]string{
		"--json", "-o", outFile,
		"-c", compose,
		"--no-probe",
	})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan --json failed: %v\nstderr: %s", err, stderr.String())
	}

	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading JSON output: %v", err)
	}

	// Decode into a raw map so we can check top-level keys without tight
	// coupling to the Result struct layout.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v\n%s", err, string(b))
	}

	for _, key := range []string{"score", "rating", "counts", "findings"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON payload missing required key %q", key)
		}
	}

	// The AI/MCP panel is render-only; it must NOT appear as a JSON key.
	for _, prohibited := range []string{"ai_mcp_panel", "aiMcpPanel", "ai_mcp_posture"} {
		if _, ok := raw[prohibited]; ok {
			t.Errorf("JSON payload must NOT contain render-only key %q", prohibited)
		}
	}
}
