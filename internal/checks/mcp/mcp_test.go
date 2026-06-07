package mcp_test

import (
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/catalog"
	_ "github.com/jwlamon/keelix/internal/checks/mcp"
	"github.com/jwlamon/keelix/internal/model"
)

// catalogGet is a local wrapper so test helpers compile before catalog entries exist.
func mustGet(t *testing.T, id string) catalog.Entry {
	t.Helper()
	if !catalog.Has(id) {
		t.Skipf("catalog entry %s not yet present (needs SLICE-B)", id)
	}
	return catalog.Get(id)
}

func findMCPCheck(t *testing.T, id string) model.Check {
	t.Helper()
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %s not registered", id)
	return nil
}

func TestPackageCompiles(t *testing.T) {
	// Just verifies the blank-import compiles.
}

func TestMCP002_WeakConfigPerms(t *testing.T) {
	mustGet(t, "MCP002")
	c := findMCPCheck(t, "MCP002")

	tests := []struct {
		name     string
		mode     string
		values   map[string]string
		wantFail bool
	}{
		{
			name: "mode 0644 on secret-bearing config is warning",
			mode: "0644",
			values: map[string]string{
				"mcpServers.s.command":   "npx",
				"mcpServers.s.env.TOKEN": "[secret]",
			},
			wantFail: true,
		},
		{
			name: "mode 0600 on secret-bearing config passes",
			mode: "0600",
			values: map[string]string{
				"mcpServers.s.command":   "npx",
				"mcpServers.s.env.TOKEN": "[secret]",
			},
			wantFail: false,
		},
		{
			name: "mode 0644 but no secrets — passes (no secret exposure risk)",
			mode: "0644",
			values: map[string]string{
				"mcpServers.s.command": "npx",
			},
			wantFail: false,
		},
		// RFX-8: owner-only modes must NOT flag.
		{
			name: "RFX-8 mode 0700 (owner-only rwx) on secret-bearing config must NOT flag",
			mode: "0700",
			values: map[string]string{
				"mcpServers.s.command":   "npx",
				"mcpServers.s.env.TOKEN": "[secret]",
			},
			wantFail: false,
		},
		{
			name: "RFX-8 mode 0660 (group read+write) on secret-bearing config must flag",
			mode: "0660",
			values: map[string]string{
				"mcpServers.s.command":   "npx",
				"mcpServers.s.env.TOKEN": "[secret]",
			},
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
					Mode:   tt.mode,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

func TestMCP003_UnpinnedLatest(t *testing.T) {
	mustGet(t, "MCP003")
	c := findMCPCheck(t, "MCP003")

	tests := []struct {
		name     string
		values   map[string]string
		wantFail bool
	}{
		{
			name: "npx with -y and no pin is warning",
			values: map[string]string{
				"mcpServers.s.command": "npx",
				"mcpServers.s.args.0":  "-y",
				"mcpServers.s.args.1":  "@modelcontextprotocol/server-filesystem",
			},
			wantFail: true,
		},
		{
			name: "npx with pinned version passes",
			values: map[string]string{
				"mcpServers.s.command": "npx",
				"mcpServers.s.args.0":  "-y",
				"mcpServers.s.args.1":  "@modelcontextprotocol/server-filesystem@1.2.3",
			},
			wantFail: false,
		},
		{
			name: "uvx with --yes and no pin is warning",
			values: map[string]string{
				"mcpServers.s.command": "uvx",
				"mcpServers.s.args.0":  "--yes",
				"mcpServers.s.args.1":  "mcp-server-fetch",
			},
			wantFail: true,
		},
		{
			name: "uvx with pinned == version passes",
			values: map[string]string{
				"mcpServers.s.command": "uvx",
				"mcpServers.s.args.0":  "mcp-server-fetch==0.6.1",
			},
			wantFail: false,
		},
		{
			name: "node (not npx/uvx/pipx) is not checked",
			values: map[string]string{
				"mcpServers.s.command": "node",
				"mcpServers.s.args.0":  "/usr/local/bin/some-server",
			},
			wantFail: false,
		},
		{
			name: "empty-string arg does not panic",
			values: map[string]string{
				"mcpServers.s.command": "npx",
				"mcpServers.s.args.0":  "-y",
				"mcpServers.s.args.1":  "",
			},
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

func TestMCP004_HttpBindNonLoopback(t *testing.T) {
	mustGet(t, "MCP004")
	c := findMCPCheck(t, "MCP004")

	tests := []struct {
		name      string
		sockets   []model.ListeningSocket
		processes []model.ProcessFact
		wantFail  bool
		wantFatal bool
	}{
		{
			name: "non-loopback MCP process socket is Critical+Fatal",
			sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "0.0.0.0", Port: 3000, PID: 42, Comm: "node"},
			},
			processes: []model.ProcessFact{
				{Comm: "node", PID: 42, Args: []string{"node", "mcp-server-http"}},
			},
			wantFail:  true,
			wantFatal: true,
		},
		{
			name: "loopback-only MCP socket does not fire MCP004",
			sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "127.0.0.1", Port: 3000, PID: 42, Comm: "node"},
			},
			processes: []model.ProcessFact{
				{Comm: "node", PID: 42, Args: []string{"node", "mcp-server"}},
			},
			wantFail: false,
		},
		{
			name:     "no sockets — not assessed",
			sockets:  nil,
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigs *model.Signals
			if tt.sockets != nil || tt.processes != nil {
				sigs = &model.Signals{
					Sockets:   tt.sockets,
					Processes: tt.processes,
				}
			}
			ctx := &model.ScanContext{Collector: sigs}
			findings := c.Run(ctx)

			if sigs == nil {
				if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
					t.Fatalf("want NotAssessed, got %+v", findings)
				}
				return
			}

			hasFail := false
			hasFatal := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityCritical {
					hasFail = true
					if f.Fatal {
						hasFatal = true
					}
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got %v findings=%+v", tt.wantFail, hasFail, findings)
			}
			if tt.wantFatal && !hasFatal {
				t.Fatalf("want Fatal finding, got %+v", findings)
			}
		})
	}
}

func TestMCP005_LocalhostHttpMCP(t *testing.T) {
	mustGet(t, "MCP005")
	c := findMCPCheck(t, "MCP005")

	tests := []struct {
		name     string
		configs  []model.ConfigFact
		wantFail bool
	}{
		{
			name: "type=http on localhost URL is Critical (SDK refinement pending)",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.s.command": "node",
					"mcpServers.s.type":    "http",
					"mcpServers.s.url":     "http://127.0.0.1:3000/mcp",
				},
			}},
			wantFail: true,
		},
		{
			name: "type=sse on localhost URL is Critical",
			configs: []model.ConfigFact{{
				Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.s.type": "sse",
					"mcpServers.s.url":  "http://localhost:8080/sse",
				},
			}},
			wantFail: true,
		},
		{
			name: "no type field (stdio server) — no finding",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.s.command": "npx",
					"mcpServers.s.args.0":  "-y",
					"mcpServers.s.args.1":  "some-server@1.0.0",
				},
			}},
			wantFail: false,
		},
		{
			name:    "no MCP configs — not assessed",
			configs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigs *model.Signals
			if tt.configs != nil {
				sigs = &model.Signals{Configs: tt.configs}
			}
			ctx := &model.ScanContext{Collector: sigs}
			findings := c.Run(ctx)

			if tt.configs == nil {
				if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
					t.Fatalf("want NotAssessed, got %+v", findings)
				}
				return
			}

			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityCritical {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got %v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

func TestMCP006_UnvettedProvenance(t *testing.T) {
	mustGet(t, "MCP006")
	c := findMCPCheck(t, "MCP006")

	tests := []struct {
		name     string
		configs  []model.ConfigFact
		wantFail bool
	}{
		{
			name: "individual GitHub package (not known org) is warning",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.rando.command": "npx",
					"mcpServers.rando.args.0":  "-y",
					"mcpServers.rando.args.1":  "github:randomuser/my-mcp-server",
				},
			}},
			wantFail: true,
		},
		{
			name: "modelcontextprotocol org package passes",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.official.command": "npx",
					"mcpServers.official.args.0":  "-y",
					"mcpServers.official.args.1":  "@modelcontextprotocol/server-filesystem@1.0.0",
				},
			}},
			wantFail: false,
		},
		{
			name:    "no MCP configs — not assessed",
			configs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigs *model.Signals
			if tt.configs != nil {
				sigs = &model.Signals{Configs: tt.configs}
			}
			ctx := &model.ScanContext{Collector: sigs}
			findings := c.Run(ctx)

			if tt.configs == nil {
				if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
					t.Fatalf("want NotAssessed, got %+v", findings)
				}
				return
			}

			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got %v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestRFX2_MCP001_ParserFed is the check-level regression test suite for RFX-2.
// It verifies that mcp001.Run() correctly handles the post-redaction markers
// ("[secret]", "[keychain-ref]") that the real collect pipeline produces, covering
// both the keychain-ref positive control (RFX-2a) and the command-less remote
// server enumeration fix (RFX-2b).
//
// The full parse->redact->check pipeline (calling collectConfigInternal on real
// fixture files and feeding the result to mcp001.Run()) is covered by
// TestRFX2_MCP001_PipelineParserFed in internal/collect/rfx2_mcp001_test.go,
// which has direct access to the unexported collectConfigInternal function.
func TestRFX2_MCP001_ParserFed(t *testing.T) {
	mustGet(t, "MCP001")
	c := findMCPCheck(t, "MCP001")

	tests := []struct {
		name     string
		configs  []model.ConfigFact
		wantFail bool // want at least one Critical non-passing finding
		wantPass bool // want at least one passing finding (no fail)
	}{
		// RFX-2(a): "[keychain-ref]" is a POSITIVE CONTROL — must not be flagged.
		// The collector emits "[keychain-ref]" (not the raw keychain: URI) when it
		// processes a macOS Keychain reference or op:// reference in a credential
		// field. MCP001 must pass a server whose only credential values are
		// "[keychain-ref]".
		{
			name: "RFX-2(a) keychain-ref server passes (positive control)",
			configs: []model.ConfigFact{{
				Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.secure.command":     "node",
					"mcpServers.secure.env.TOKEN":   "[keychain-ref]",
					"mcpServers.secure.env.API_KEY": "[keychain-ref]",
				},
			}},
			wantPass: true,
		},
		// RFX-2(a) inlined-secret server must fail.
		// The collector emits "[secret]" for plaintext credentials. MCP001 must
		// flag a server with a "[secret]" env value.
		{
			name: "RFX-2(a) inlined-secret server fails",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.leaky.command":     "npx",
					"mcpServers.leaky.env.API_KEY": "[secret]",
				},
			}},
			wantFail: true,
		},
		// RFX-2(b): remote HTTP server with NO .command key but a Bearer header
		// that the collector marked "[secret]". Before this fix, mcpServerNames
		// only enumerated servers with a .command key, so this server was silently
		// skipped and the finding was never emitted.
		{
			name: "RFX-2(b) remote http server (url only, no command) with secret header fails",
			configs: []model.ConfigFact{{
				Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.remote.type":                  "http",
					"mcpServers.remote.url":                   "https://api.example.com/mcp",
					"mcpServers.remote.headers.Authorization": "[secret]",
				},
			}},
			wantFail: true,
		},
		// RFX-2(b)+(a): remote http server (url only, no command) whose credential
		// fields contain only "[keychain-ref]" — must pass (positive control).
		{
			name: "RFX-2(b)+(a) remote http server with keychain-ref header passes",
			configs: []model.ConfigFact{{
				Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.remote.type":                  "sse",
					"mcpServers.remote.url":                   "https://api.example.com/sse",
					"mcpServers.remote.headers.Authorization": "[keychain-ref]",
				},
			}},
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{Configs: tt.configs}}
			findings := c.Run(ctx)
			if tt.wantFail {
				for _, f := range findings {
					if !f.Passed && f.Severity == model.SeverityCritical {
						return
					}
				}
				t.Fatalf("want Critical fail finding, got %+v", findings)
			}
			if tt.wantPass {
				for _, f := range findings {
					if f.Passed {
						return
					}
				}
				t.Fatalf("want pass finding, got %+v", findings)
			}
		})
	}
}

func TestMCP001_PlaintextSecret(t *testing.T) {
	mustGet(t, "MCP001")
	c := findMCPCheck(t, "MCP001")

	tests := []struct {
		name     string
		configs  []model.ConfigFact
		wantFail bool
		wantPass bool
	}{
		{
			name: "secret marker triggers finding",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.myserver.command":     "npx",
					"mcpServers.myserver.env.API_KEY": "[secret]",
				},
			}},
			wantFail: true,
		},
		{
			name: "keychain-ref marker (post-redaction) is NOT a secret — no finding",
			configs: []model.ConfigFact{{
				Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.myserver.command":   "node",
					"mcpServers.myserver.env.TOKEN": "[keychain-ref]",
				},
			}},
			wantPass: true,
		},
		{
			name:    "no MCP configs — not assessed",
			configs: nil,
			// neither fail nor pass, StatusNotAssessed
		},
		{
			name: "header value is secret marker",
			configs: []model.ConfigFact{{
				Source: "~/.codeium/windsurf/mcp_config.json", SchemaID: "windsurf-mcp", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.ws.command":               "uvx",
					"mcpServers.ws.headers.Authorization": "[secret]",
				},
			}},
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigs *model.Signals
			if tt.configs != nil {
				sigs = &model.Signals{Configs: tt.configs}
			}
			ctx := &model.ScanContext{Collector: sigs}
			findings := c.Run(ctx)

			if tt.configs == nil {
				// expect StatusNotAssessed
				if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
					t.Fatalf("want single NotAssessed finding, got %+v", findings)
				}
				return
			}
			if tt.wantFail {
				for _, f := range findings {
					if !f.Passed && f.Severity == model.SeverityCritical {
						return
					}
				}
				t.Fatalf("want Critical fail finding, got %+v", findings)
			}
			if tt.wantPass {
				for _, f := range findings {
					if f.Passed {
						return
					}
				}
				t.Fatalf("want pass finding, got %+v", findings)
			}
		})
	}
}

func TestMCP008_PermissionBypassAmplifier(t *testing.T) {
	mustGet(t, "MCP008")
	c := findMCPCheck(t, "MCP008")

	tests := []struct {
		name     string
		configs  []model.ConfigFact
		wantFail bool
	}{
		{
			name: "bypassPermissionsModeEnabled=true is warning",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"bypassPermissionsModeEnabled": "true",
					"mcpServers.s.command":         "npx",
				},
			}},
			wantFail: true,
		},
		{
			name: "allowAllBrowserActions=true in claude-desktop-config is warning",
			configs: []model.ConfigFact{{
				Source:   "~/Library/Application Support/Claude/claude_desktop_config.json",
				SchemaID: "claude-desktop-config", SchemaKnown: true,
				Values: map[string]string{
					"preferences.allowAllBrowserActions": "true",
					"mcpServers.s.command":               "node",
				},
			}},
			wantFail: true,
		},
		{
			name: "broad trustedFolders entry is warning",
			configs: []model.ConfigFact{{
				Source:   "~/Library/Application Support/Claude/claude_desktop_config.json",
				SchemaID: "claude-desktop-config", SchemaKnown: true,
				Values: map[string]string{
					"preferences.localAgentModeTrustedFolders.0": "/",
					"mcpServers.s.command":                       "node",
				},
			}},
			wantFail: true,
		},
		{
			name: "no bypass flags passes",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.s.command": "npx",
				},
			}},
			wantFail: false,
		},
		{
			name:    "no MCP configs — not assessed",
			configs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigs *model.Signals
			if tt.configs != nil {
				sigs = &model.Signals{Configs: tt.configs}
			}
			ctx := &model.ScanContext{Collector: sigs}
			findings := c.Run(ctx)

			if tt.configs == nil {
				if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
					t.Fatalf("want NotAssessed, got %+v", findings)
				}
				return
			}

			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got %v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

func TestMCP009_KnownCVETooling(t *testing.T) {
	mustGet(t, "MCP009")
	c := findMCPCheck(t, "MCP009")

	tests := []struct {
		name      string
		processes []model.ProcessFact
		configs   []model.ConfigFact
		wantFail  bool
	}{
		{
			name: "MCP Inspector process is Critical",
			processes: []model.ProcessFact{
				{Comm: "node", PID: 100, Args: []string{"node", "@modelcontextprotocol/inspector"}},
			},
			wantFail: true,
		},
		{
			name: "mcp-inspector package in config args is Critical",
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.s.command": "npx",
					"mcpServers.s.args.0":  "-y",
					"mcpServers.s.args.1":  "@modelcontextprotocol/inspector",
				},
			}},
			wantFail: true,
		},
		{
			name: "unrelated process and clean config passes",
			processes: []model.ProcessFact{
				{Comm: "node", PID: 200, Args: []string{"node", "some-other-server"}},
			},
			configs: []model.ConfigFact{{
				Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.s.command": "npx",
					"mcpServers.s.args.0":  "@modelcontextprotocol/server-filesystem@1.0.0",
				},
			}},
			wantFail: false,
		},
		{
			name:     "no data — not assessed",
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sigs *model.Signals
			if tt.processes != nil || tt.configs != nil {
				sigs = &model.Signals{
					Processes: tt.processes,
					Configs:   tt.configs,
				}
			}
			ctx := &model.ScanContext{Collector: sigs}
			findings := c.Run(ctx)

			if sigs == nil {
				if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
					t.Fatalf("want NotAssessed, got %+v", findings)
				}
				return
			}

			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityCritical {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got %v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

func TestMCP007_NilProbe_NotAssessed(t *testing.T) {
	mustGet(t, "MCP007")
	c := findMCPCheck(t, "MCP007")
	for _, tt := range []struct {
		name string
		sigs *model.Signals
	}{
		{name: "nil collector", sigs: nil},
		{name: "collector with no MCPProbe", sigs: &model.Signals{}},
		{name: "collector with MCPProbe nil field", sigs: &model.Signals{MCPProbe: nil}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			findings := c.Run(&model.ScanContext{Collector: tt.sigs})
			if len(findings) != 1 {
				t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
			}
			if findings[0].Status != model.StatusNotAssessed {
				t.Fatalf("want StatusNotAssessed, got %v", findings[0].Status)
			}
		})
	}
}

func TestMCP007_DriftedTool_Critical(t *testing.T) {
	mustGet(t, "MCP007")
	c := findMCPCheck(t, "MCP007")
	ctx := &model.ScanContext{Collector: &model.Signals{MCPProbe: &model.MCPProbe{
		Servers: []model.MCPServerProbe{{
			Client:      "~/.config/test/mcp.json",
			Name:        "alpha",
			Transport:   "stdio",
			Reached:     true,
			SandboxTier: "tier0",
			Tools: []model.MCPToolFact{
				{Name: "search", DescHash: "abc", Drifted: false, FirstSeen: false},
				{Name: "exfiltrate", DescHash: "def", Drifted: true, FirstSeen: false},
			},
		}},
	}}}
	findings := c.Run(ctx)
	var crit *model.Finding
	for i := range findings {
		if findings[i].Severity == model.SeverityCritical && !findings[i].Passed {
			crit = &findings[i]
		}
	}
	if crit == nil {
		t.Fatalf("want a Critical drift finding, got %+v", findings)
	}
	if crit.CheckID != "MCP007" {
		t.Errorf("want CheckID MCP007, got %q", crit.CheckID)
	}
	if !strings.Contains(crit.Evidence, "alpha") || !strings.Contains(crit.Evidence, "exfiltrate") {
		t.Errorf("evidence must name server+tool, got %q", crit.Evidence)
	}
	if !strings.Contains(crit.Evidence, "baseline") {
		t.Errorf("evidence must mention the baseline, got %q", crit.Evidence)
	}
}

func TestMCP007_FirstSeenOnly_Pass(t *testing.T) {
	mustGet(t, "MCP007")
	c := findMCPCheck(t, "MCP007")
	ctx := &model.ScanContext{Collector: &model.Signals{MCPProbe: &model.MCPProbe{
		Servers: []model.MCPServerProbe{{
			Name:    "alpha",
			Reached: true,
			Tools: []model.MCPToolFact{
				{Name: "search", DescHash: "abc", FirstSeen: true},
				{Name: "list", DescHash: "xyz", FirstSeen: true},
			},
		}},
	}}}
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("first-run inventory must be a single Pass, got %+v", findings)
	}
}

// TestMCP007_CorruptBaseline_Critical verifies the SBX-9(b) guarantee: when
// MCPProbe.CorruptBaseline is true MCP007 must emit a Critical finding so the
// operator knows that drift detection is impaired (all tools appear FirstSeen).
func TestMCP007_CorruptBaseline_Critical(t *testing.T) {
	mustGet(t, "MCP007")
	c := findMCPCheck(t, "MCP007")
	ctx := &model.ScanContext{Collector: &model.Signals{MCPProbe: &model.MCPProbe{
		CorruptBaseline: true,
	}}}
	findings := c.Run(ctx)
	if len(findings) == 0 {
		t.Fatalf("want at least one finding for corrupt baseline, got none")
	}
	var crit *model.Finding
	for i := range findings {
		if findings[i].Severity == model.SeverityCritical && !findings[i].Passed {
			crit = &findings[i]
			break
		}
	}
	if crit == nil {
		t.Fatalf("want a Critical finding for corrupt baseline, got %+v", findings)
	}
	if crit.CheckID != "MCP007" {
		t.Errorf("want CheckID MCP007, got %q", crit.CheckID)
	}
	if !strings.Contains(strings.ToLower(crit.Detail+crit.Evidence), "corrupt") {
		t.Errorf("finding detail/evidence must mention 'corrupt', got detail=%q evidence=%q",
			crit.Detail, crit.Evidence)
	}
}

// TestRFX3_MCP003_ParserFed is the parser-fed regression test for RFX-3/MCP003.
// It verifies that the pinned-version detection logic is correct against real
// flattened arg values as they arrive from the collect pipeline after RFX-1
// (args survive verbatim — no redaction on structural fields).
//
// Before RFX-1, args could be redacted, so the pin-detection heuristic was never
// exercised on real package specs. This test locks the expected behaviour:
//
//   - "npx -y @upstash/context7-mcp@1.0.8" MUST pass  (the @<ver> suffix is present)
//   - "npx -y @foo/bar"                     MUST fail  (no version token)
//
// Values are the post-redaction output of parseCursorMCP / parseClaudeJSON on a
// real config — args.* fields are structural and survive verbatim per the RFX-1
// key-path-aware redaction rule.
func TestRFX3_MCP003_ParserFed(t *testing.T) {
	mustGet(t, "MCP003")
	c := findMCPCheck(t, "MCP003")

	tests := []struct {
		name     string
		values   map[string]string
		wantFail bool
	}{
		{
			// Real-world context7 server with explicit version pin.
			// Post-RFX-1 pipeline: args survive verbatim — "@upstash/context7-mcp@1.0.8"
			// is NOT redacted. MCP003 must see the "@1.0.8" suffix and PASS.
			name: "RFX-3 npx -y @upstash/context7-mcp@1.0.8 is pinned (must pass)",
			values: map[string]string{
				"mcpServers.context7.command": "npx",
				"mcpServers.context7.args.0":  "-y",
				"mcpServers.context7.args.1":  "@upstash/context7-mcp@1.0.8",
			},
			wantFail: false,
		},
		{
			// Same runner, same auto-install flag, but no version pin.
			// Post-RFX-1 pipeline: "@foo/bar" arrives verbatim. No "@" after the
			// first character in any arg other than the scoped-package leading "@".
			// MCP003 must flag this as unpinned.
			name: "RFX-3 npx -y @foo/bar has no version pin (must fail)",
			values: map[string]string{
				"mcpServers.unpinned.command": "npx",
				"mcpServers.unpinned.args.0":  "-y",
				"mcpServers.unpinned.args.1":  "@foo/bar",
			},
			wantFail: true,
		},
		{
			// A scoped package with a version pin at the org level should not confuse
			// the check: "@scope/pkg@2.0.0" — pin token present at position > 0.
			name: "RFX-3 npx -y @scope/pkg@2.0.0 is pinned (must pass)",
			values: map[string]string{
				"mcpServers.pinned.command": "npx",
				"mcpServers.pinned.args.0":  "-y",
				"mcpServers.pinned.args.1":  "@scope/pkg@2.0.0",
			},
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source: "~/.cursor/mcp.json", SchemaID: "cursor-mcp", SchemaKnown: true,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestRFX3_MCP006_ParserFed is the parser-fed regression test for RFX-3/MCP006.
// It verifies that provenance detection is correct against real flattened arg values
// as they arrive from the collect pipeline after RFX-1 (args survive verbatim).
//
// Key cases:
//   - "@scope/unknown-pkg"                      MUST flag (unverified npm org scope)
//   - "github:rando/x"                          MUST flag (individual GitHub repo ref)
//   - "@modelcontextprotocol/server-filesystem" MUST pass (verified org)
//
// Values simulate post-RFX-1 collect output: structural fields (args.*) are
// never redacted, so the check sees the verbatim package spec string.
func TestRFX3_MCP006_ParserFed(t *testing.T) {
	mustGet(t, "MCP006")
	c := findMCPCheck(t, "MCP006")

	tests := []struct {
		name     string
		values   map[string]string
		wantFail bool
	}{
		{
			// Unverified npm org scope — "@scope" is not in verifiedMCPOrgs.
			// Post-RFX-1 pipeline: args.* values arrive verbatim.
			// MCP006 must flag this as unverified provenance.
			name: "RFX-3 @scope/unknown-pkg is unverified (must flag)",
			values: map[string]string{
				"mcpServers.unknown.command": "npx",
				"mcpServers.unknown.args.0":  "-y",
				"mcpServers.unknown.args.1":  "@scope/unknown-pkg",
			},
			wantFail: true,
		},
		{
			// Direct GitHub repo reference — not an npm package at all.
			// MCP006 must flag the "github:" prefix.
			name: "RFX-3 github:rando/x is an unverified direct-repo ref (must flag)",
			values: map[string]string{
				"mcpServers.rando.command": "npx",
				"mcpServers.rando.args.0":  "-y",
				"mcpServers.rando.args.1":  "github:rando/x",
			},
			wantFail: true,
		},
		{
			// Verified org scope — must pass.
			name: "RFX-3 @modelcontextprotocol/server-filesystem is verified (must pass)",
			values: map[string]string{
				"mcpServers.official.command": "npx",
				"mcpServers.official.args.0":  "-y",
				"mcpServers.official.args.1":  "@modelcontextprotocol/server-filesystem@1.0.0",
			},
			wantFail: false,
		},
		{
			// Verified org scope without version pin — provenance is still verified
			// (MCP006 is about provenance, not pinning — that is MCP003's job).
			name: "RFX-3 @anthropic/mcp-server without pin is verified provenance (must pass)",
			values: map[string]string{
				"mcpServers.anthropic.command": "npx",
				"mcpServers.anthropic.args.0":  "-y",
				"mcpServers.anthropic.args.1":  "@anthropic/mcp-server",
			},
			wantFail: false,
		},
		{
			// Unscoped (plain) package name in the official registry publisher
			// allowlist — must pass. "mcp-server-fetch" is in verifiedRegistryPublishers
			// so isVerifiedProvenance returns true after stripping the "==0.6.1" pin.
			name: "RFX-3 plain unscoped package name in verified publisher list does not fire MCP006",
			values: map[string]string{
				"mcpServers.plain.command": "uvx",
				"mcpServers.plain.args.0":  "mcp-server-fetch==0.6.1",
			},
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestMCP006_Run_OCIAndBareArgs verifies that Run() correctly routes OCI image
// args and bare package name args through isVerifiedProvenance(), closing the
// dead-code gap identified in the quality review (D.6).
//
// Before the fix: OCI images and bare names were silently skipped — an untrusted
// OCI image was never flagged, and a trusted pinned OCI image was never passed.
// After the fix: Run() dispatches all three arg classes (npm scoped, OCI, bare)
// through isVerifiedProvenance() so the allowlists are actually exercised.
func TestMCP006_Run_OCIAndBareArgs(t *testing.T) {
	mustGet(t, "MCP006")
	c := findMCPCheck(t, "MCP006")

	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name     string
		values   map[string]string
		wantFail bool // want at least one Warning non-passing finding
	}{
		// OCI: untrusted registry — must be flagged.
		// args.0 is the OCI image directly (no docker subcommand prefix) as seen in
		// MCP configs that use a container runtime as the command (e.g. "docker").
		{
			name: "OCI untrusted registry image is flagged",
			values: map[string]string{
				"mcpServers.evil.command": "docker",
				"mcpServers.evil.args.0":  "docker.io/evil/mcp-server@sha256:" + sha,
			},
			wantFail: true,
		},
		// OCI: trusted registry but NO digest pin — must be flagged (floating tag is not safe).
		{
			name: "OCI trusted registry without digest pin is flagged",
			values: map[string]string{
				"mcpServers.unpinned.command": "docker",
				"mcpServers.unpinned.args.0":  "ghcr.io/modelcontextprotocol/server-git",
			},
			wantFail: true,
		},
		// OCI: trusted registry WITH sha256 digest — must pass (verified pinned image).
		{
			name: "OCI trusted pinned image passes",
			values: map[string]string{
				"mcpServers.pinned.command": "docker",
				"mcpServers.pinned.args.0":  "ghcr.io/modelcontextprotocol/server-git@sha256:" + sha,
			},
			wantFail: false,
		},
		// Bare name: official registry publisher — must pass.
		{
			name: "bare name in verifiedRegistryPublishers passes",
			values: map[string]string{
				"mcpServers.official.command": "uvx",
				"mcpServers.official.args.0":  "mcp-server-git==1.0.0",
			},
			wantFail: false,
		},
		// Bare name: unknown package — must be flagged.
		{
			name: "bare name not in verifiedRegistryPublishers is flagged",
			values: map[string]string{
				"mcpServers.unknown.command": "uvx",
				"mcpServers.unknown.args.0":  "some-random-mcp-server",
			},
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source: "~/.claude.json", SchemaID: "claude-json", SchemaKnown: true,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestSF4_MCP006_DockerSubcommandSkip tests SF-4 (a): when command=docker and
// args start with a container subcommand like "run", the subcommand and flags
// must be skipped and only the OCI image reference evaluated for provenance.
func TestSF4_MCP006_DockerSubcommandSkip(t *testing.T) {
	mustGet(t, "MCP006")
	c := findMCPCheck(t, "MCP006")

	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name     string
		values   map[string]string
		wantFail bool
	}{
		{
			// SF-4 (a): docker run with a pinned trusted OCI image — must NOT flag.
			// Before fix: "run" was treated as a bare package name and flagged.
			name: "docker run --rm -i trusted-pinned-OCI must NOT flag",
			values: map[string]string{
				"mcpServers.git.command": "docker",
				"mcpServers.git.args.0":  "run",
				"mcpServers.git.args.1":  "--rm",
				"mcpServers.git.args.2":  "-i",
				"mcpServers.git.args.3":  "ghcr.io/modelcontextprotocol/server-git@sha256:" + sha,
			},
			wantFail: false,
		},
		{
			// SF-4 (a): docker run with an untrusted OCI image — must flag.
			name: "docker run with untrusted image must flag",
			values: map[string]string{
				"mcpServers.evil.command": "docker",
				"mcpServers.evil.args.0":  "run",
				"mcpServers.evil.args.1":  "--rm",
				"mcpServers.evil.args.2":  "docker.io/evil/mcp-server@sha256:" + sha,
			},
			wantFail: true,
		},
		{
			// SF-4 (a): docker run with trusted base but no digest pin — must flag.
			name: "docker run trusted-base no-digest must flag",
			values: map[string]string{
				"mcpServers.unpinned.command": "docker",
				"mcpServers.unpinned.args.0":  "run",
				"mcpServers.unpinned.args.1":  "--rm",
				"mcpServers.unpinned.args.2":  "ghcr.io/modelcontextprotocol/server-git",
			},
			wantFail: true,
		},
		{
			// SF-4 (a): podman run with pinned trusted OCI image — must NOT flag.
			name: "podman run trusted-pinned-OCI must NOT flag",
			values: map[string]string{
				"mcpServers.podman.command": "podman",
				"mcpServers.podman.args.0":  "run",
				"mcpServers.podman.args.1":  "--rm",
				"mcpServers.podman.args.2":  "-i",
				"mcpServers.podman.args.3":  "ghcr.io/modelcontextprotocol/server-filesystem@sha256:" + sha,
			},
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source:   "~/Library/Application Support/Claude/claude_desktop_config.json",
					SchemaID: "claude-desktop-config", SchemaKnown: true,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestSF4_MCP006_JSRSchemeStrip tests SF-4 (b): jsr:/npm: scheme stripping.
func TestSF4_MCP006_JSRSchemeStrip(t *testing.T) {
	mustGet(t, "MCP006")
	c := findMCPCheck(t, "MCP006")

	tests := []struct {
		name     string
		values   map[string]string
		wantFail bool
	}{
		{
			// SF-4 (b): jsr:@modelcontextprotocol/server-filesystem — verified after strip.
			// Before fix: jsr: prefix caused barePackageName to return "jsr:" → unknown.
			name: "jsr:@modelcontextprotocol/server-filesystem must NOT flag",
			values: map[string]string{
				"mcpServers.jsr.command": "npx",
				"mcpServers.jsr.args.0":  "jsr:@modelcontextprotocol/server-filesystem",
			},
			wantFail: false,
		},
		{
			// SF-4 (b): jsr:@randomuser/some-mcp — still unverified after strip.
			name: "jsr:@randomuser/some-mcp must flag",
			values: map[string]string{
				"mcpServers.jsr.command": "npx",
				"mcpServers.jsr.args.0":  "jsr:@randomuser/some-mcp",
			},
			wantFail: true,
		},
		{
			// SF-4 (b): npm:@anthropic/mcp-server — verified after strip.
			name: "npm:@anthropic/mcp-server must NOT flag",
			values: map[string]string{
				"mcpServers.npm.command": "npx",
				"mcpServers.npm.args.0":  "npm:@anthropic/mcp-server",
			},
			wantFail: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source:   "~/.claude.json",
					SchemaID: "claude-json", SchemaKnown: true,
					Values: tt.values,
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestSF4_MCP006_MegascopeTrimmed tests SF-4 (c): megascopes are no longer verified.
func TestSF4_MCP006_MegascopeTrimmed(t *testing.T) {
	mustGet(t, "MCP006")
	c := findMCPCheck(t, "MCP006")

	// These scopes are megascopes that must no longer pass provenance.
	megascopeArgs := []struct {
		name string
		arg  string
	}{
		{"github", "@github/mcp-server"},
		{"google", "@google/some-mcp"},
		{"microsoft", "@microsoft/mcp"},
		{"azure", "@azure/mcp-server"},
		{"aws", "@aws/mcp-server"},
		{"cloudflare", "@cloudflare/mcp-server"},
	}

	for _, tc := range megascopeArgs {
		t.Run(tc.name+" megascope must flag", func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source:   "~/.claude.json",
					SchemaID: "claude-json", SchemaKnown: true,
					Values: map[string]string{
						"mcpServers.s.command": "npx",
						"mcpServers.s.args.0":  tc.arg,
					},
				}},
			}}
			findings := c.Run(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if !hasFail {
				t.Fatalf("megascope %q should flag as unverified, but no warning finding", tc.arg)
			}
		})
	}
}

func TestAllMCPChecksRegistered(t *testing.T) {
	want := []string{
		"MCP001", "MCP002", "MCP003", "MCP004", "MCP005",
		"MCP006", "MCP007", "MCP008", "MCP009",
	}
	registered := map[string]bool{}
	for _, c := range model.Registered() {
		registered[c.ID()] = true
	}
	for _, id := range want {
		if !catalog.Has(id) {
			t.Skipf("catalog entry %s not yet present (needs SLICE-B)", id)
		}
		if !registered[id] {
			t.Errorf("check %s not registered", id)
		}
	}
}
