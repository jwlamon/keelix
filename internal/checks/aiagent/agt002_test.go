package aiagent_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

// fullTrifectaSignals returns a Signals with all three trifecta legs in ONE config:
//   - private-data: fs.workspaceOnly==false
//   - untrusted-ingest: browser.enabled==true
//   - exfil: mcpServers.slack.command present (messaging channel)
func fullTrifectaSignals() *model.Signals {
	return &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"tools.fs.workspaceOnly":   "false",
					"browser.enabled":          "true",
					"mcpServers.slack.command": "uvx",
					"mcpServers.slack.args.0":  "mcp-slack",
				},
			},
		},
	}
}

func TestAGT002_FullTrifecta(t *testing.T) {
	c := findCheck(t, "AGT002")
	findings := c.Run(makeCtxWithCollector(fullTrifectaSignals()))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			found = true
			if f.Confidence != model.ConfidenceMedium {
				t.Errorf("AGT002: want ConfidenceMedium, got %v", f.Confidence)
			}
			if f.Severity != model.SeverityCritical {
				t.Errorf("AGT002: want Critical, got %s", f.Severity)
			}
			if f.Metadata == nil || f.Metadata["capability_proxy"] != "true" {
				t.Errorf("AGT002: want Metadata[capability_proxy]=true, got %v", f.Metadata)
			}
			if !f.Fatal {
				t.Error("AGT002: want Fatal=true (from catalog)")
			}
		}
	}
	if !found {
		t.Fatalf("AGT002: want failing finding for full trifecta, got %+v", findings)
	}
}

func TestAGT002_MissingExfil_NoFiring(t *testing.T) {
	// No messaging/exfil MCP server — trifecta incomplete.
	c := findCheck(t, "AGT002")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"tools.fs.workspaceOnly": "false",
					"browser.enabled":        "true",
					// no messaging MCP
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			t.Errorf("AGT002: should NOT fire when exfil leg absent, got %+v", f)
		}
	}
}

func TestAGT002_MissingPrivateData_NoFiring(t *testing.T) {
	// fs.workspaceOnly=="true" => no private-data access leg.
	c := findCheck(t, "AGT002")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"tools.fs.workspaceOnly":   "true",
					"browser.enabled":          "true",
					"mcpServers.slack.command": "uvx",
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			t.Errorf("AGT002: should NOT fire when private-data leg absent, got %+v", f)
		}
	}
}

func TestAGT002_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT002")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT002: want single NotAssessed when Collector==nil, got %+v", findings)
	}
}

// TestAGT002_SplitLegs_NoFiring verifies that legs split across TWO DISTINCT
// configs do NOT fire AGT002. This is the RFX-4 Bug-1 regression test:
// before the fix, the three legs were ORed across the entire Signals, so one
// config's private-data + a different config's exfil wrongly combined into a RED.
func TestAGT002_SplitLegs_NoFiring(t *testing.T) {
	c := findCheck(t, "AGT002")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				// Config A: private-data + untrusted-ingest (no exfil).
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"tools.fs.workspaceOnly": "false",
					"browser.enabled":        "true",
					// no messaging MCP
				},
			},
			{
				// Config B: exfil only (no private-data, no untrusted-ingest).
				SchemaID:    "claude-code-settings",
				SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.slack.command": "uvx",
					"mcpServers.slack.args.0":  "mcp-slack",
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			t.Errorf("AGT002: must NOT fire when legs are split across two distinct configs, got %+v", f)
		}
	}
}

// TestAGT002_RemoteSlackMCP_Fires verifies that a remote (command-less) Slack
// MCP server — registered only via url/type keys — satisfies the exfil leg and
// causes AGT002 to fire when the other two legs are also present.
// This is the RFX-4 Bug-2 regression test: before the fix, McpServerNames only
// enumerated servers with a ".command" key, so a url-only Slack server was
// invisible to the exfil leg.
func TestAGT002_RemoteSlackMCP_Fires(t *testing.T) {
	c := findCheck(t, "AGT002")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"tools.fs.workspaceOnly": "false",
					"browser.enabled":        "true",
					// Remote Slack MCP — NO "command" key, only url+type.
					"mcpServers.slack.url":  "https://mcp.slack.com/",
					"mcpServers.slack.type": "http",
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	found := false
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatalf("AGT002: want failing finding for trifecta with remote command-less Slack MCP, got %+v", findings)
	}
}

// TestAGT002_OneConfigFullTrifecta_Fires confirms the happy-path: a single
// config carrying all three legs fires AGT002 (parser-fed synthetic variant
// checking per-config scoping logic directly in the aiagent package).
func TestAGT002_OneConfigFullTrifecta_Fires(t *testing.T) {
	c := findCheck(t, "AGT002")
	findings := c.Run(makeCtxWithCollector(fullTrifectaSignals()))
	found := false
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatalf("AGT002: want failing finding when all three legs in one config, got %+v", findings)
	}
}

// TestAGT002_MissingIngest_NoFiring verifies that the absence of the
// untrusted-ingest leg prevents firing even when private-data and exfil are present.
func TestAGT002_MissingIngest_NoFiring(t *testing.T) {
	c := findCheck(t, "AGT002")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"tools.fs.workspaceOnly": "false",
					// no browser.enabled, no web search provider — untrusted-ingest absent
					"mcpServers.slack.command": "uvx",
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT002" && f.IsFail() {
			t.Errorf("AGT002: must NOT fire when untrusted-ingest leg absent, got %+v", f)
		}
	}
}
