package engine_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestHelperMCPServer is not a real test. When invoked by an integration test
// via os.Args[0] with KEELIX_TEST_MCP_SERVER=1 set, it impersonates a stdio
// JSON-RPC 2.0 MCP server so the active probe can drive a REAL subprocess
// through sandbox.NewRunner().Start. The single advertised tool's description
// is taken from KEELIX_TEST_MCP_DESC, which lets a drift test change the
// description between two runs of the same binary.
func TestHelperMCPServer(t *testing.T) {
	// When KEELIX_TEST_MCP_SERVER=1, TestMain (testmain_test.go) intercepts
	// the process before reaching here and calls os.Exit(0) itself. That path
	// is explicitly permitted by the testing package. We guard here as a
	// belt-and-suspenders safety net; by this point TestMain would have already
	// exited, so this branch is unreachable during subprocess invocations.
	if os.Getenv("KEELIX_TEST_MCP_SERVER") != "1" {
		return // ordinary test run: do nothing
	}
	t.Skip("subprocess entry-point handled by TestMain; this path should be unreachable")
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func runHelperMCPServer() {
	desc := os.Getenv("KEELIX_TEST_MCP_DESC")
	if desc == "" {
		desc = "original description"
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	write := func(id json.RawMessage, result any) {
		env := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "result": result}
		b, _ := json.Marshal(env)
		fmt.Fprintf(out, "%s\n", b)
		out.Flush()
	}

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcReq
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			write(req.ID, map[string]any{
				"protocolVersion": "2025-11-25",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fake-mcp", "version": "0.0.1"},
			})
		case "notifications/initialized":
			// notification: no response
		case "tools/list":
			write(req.ID, map[string]any{
				"tools": []map[string]any{
					{"name": "do_thing", "description": desc},
				},
			})
		default:
			if len(req.ID) > 0 {
				write(req.ID, map[string]any{})
			}
		}
	}
}

// writeMCPSignalsFixture writes a Signals JSON whose Configs carry one MCP
// server ("fake") whose stdio command re-execs THIS test binary as the
// SLF.2 helper server, with the given tool description. It returns the path
// for Options.SignalsPath. selfBin is os.Args[0] (the test binary).
func writeMCPSignalsFixture(t *testing.T, dir, selfBin, desc string) string {
	t.Helper()
	sig := map[string]any{
		"version": "1.0.0",
		"configs": []map[string]any{
			{
				"source":       "~/.cursor/mcp.json",
				"schema_id":    "cursor-mcp",
				"schema_known": true,
				"values": map[string]string{
					"mcpServers.fake.command": selfBin,
					"mcpServers.fake.args.0":  "-test.run",
					"mcpServers.fake.args.1":  "TestHelperMCPServer",
					"mcpServers.fake.env.0":   "KEELIX_TEST_MCP_SERVER=1",
					"mcpServers.fake.env.1":   "KEELIX_TEST_MCP_DESC=" + desc,
				},
			},
		},
	}
	b, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal signals fixture: %v", err)
	}
	p := filepath.Join(dir, "signals.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write signals fixture: %v", err)
	}
	return p
}
