package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// The CLI test reuses the engine package's spawnable fake MCP server contract:
// a child process is the test binary itself, re-exec'd with these env vars.
const (
	envMCPServer = "KEELIX_TEST_MCP_SERVER"
	envMCPDesc   = "KEELIX_TEST_MCP_DESC"
)

// TestCLIHelperMCPServer impersonates a stdio MCP server when the cli test
// binary is re-exec'd by the sandbox. Mirrors the engine package helper so the
// cli package is self-contained.
func TestCLIHelperMCPServer(t *testing.T) {
	if os.Getenv(envMCPServer) != "1" {
		return
	}
	desc := os.Getenv(envMCPDesc)
	if desc == "" {
		desc = "original description"
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	write := func(id json.RawMessage, result any) {
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
		fmt.Fprintf(out, "%s\n", b)
		out.Flush()
	}
	for in.Scan() {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			write(req.ID, map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "serverInfo": map[string]any{"name": "fake", "version": "0"}})
		case "notifications/initialized":
		case "tools/list":
			write(req.ID, map[string]any{"tools": []map[string]any{{"name": "do_thing", "description": desc}}})
		}
	}
	os.Exit(0)
}

func writeCLIMCPSignals(t *testing.T, dir, selfBin string) string {
	t.Helper()
	sig := map[string]any{
		"version": "1.0.0",
		"configs": []map[string]any{{
			"source":       "~/.cursor/mcp.json",
			"schema_id":    "cursor-mcp",
			"schema_known": true,
			"values": map[string]string{
				"mcpServers.fake.command": selfBin,
				"mcpServers.fake.args.0":  "-test.run",
				"mcpServers.fake.args.1":  "TestCLIHelperMCPServer",
				"mcpServers.fake.env.0":   envMCPServer + "=1",
				"mcpServers.fake.env.1":   envMCPDesc + "=original description",
			},
		}},
	}
	b, _ := json.Marshal(sig)
	p := filepath.Join(dir, "signals.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write signals: %v", err)
	}
	return p
}

func runScanJSON(t *testing.T, args ...string) *model.Result {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "result.json")
	cmd := newScanCmd()
	full := append([]string{"--json", "-o", out}, args...)
	cmd.SetArgs(full)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan %v: %v", full, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var r model.Result
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return &r
}

func TestScan_NoProbeByDefault(t *testing.T) {
	compose := filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml")
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	sigPath := writeCLIMCPSignals(t, t.TempDir(), selfBin)

	// Plain scan: the active MCP probe MUST NOT run even though a stdio MCP
	// server is present in the signals.
	r := runScanJSON(t, "-c", compose, "--no-probe", "--signals", sigPath)
	if r.Collector != nil && r.Collector.MCPProbe != nil {
		t.Fatalf("default scan ran the MCP probe: MCPProbe=%+v; want nil", r.Collector.MCPProbe)
	}
}

func TestScan_ProbeWithConsentYes(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("sandbox runner unsupported on %s", runtime.GOOS)
	}
	compose := filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml")
	selfBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	sigPath := writeCLIMCPSignals(t, home, selfBin)

	// --probe-mcp-yes is the non-interactive consent flag (SLE).
	r := runScanJSON(t, "-c", compose, "--no-probe", "--signals", sigPath,
		"--probe-mcp", "--probe-mcp-yes")
	if r.Collector == nil || r.Collector.MCPProbe == nil {
		t.Fatalf("scan --probe-mcp-yes did not populate MCPProbe")
	}
	var found bool
	for _, s := range r.Collector.MCPProbe.Servers {
		if s.Name == "fake" && s.Reached && len(s.Tools) == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("MCPProbe missing reached server 'fake' with one tool: %+v",
			r.Collector.MCPProbe)
	}
}
