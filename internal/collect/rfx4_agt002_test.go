package collect

// TestRFX4_AGT002_PipelineParserFed is the PARSER-FED regression test for RFX-4.
// It calls collectConfigInternal on real fixture files and feeds the resulting
// model.ConfigFact — after the full parse->redact pipeline has run — to
// AGT002.Run() via the registered model.Check interface.
//
// This is the test that the spec meta-rule mandates: it exercises the complete
//   parse -> redact -> check
// pipeline end-to-end, guarding against bugs that synthetic-signal unit tests
// (which pre-populate ConfigFact.Values directly) can never catch.
//
// Two bugs guarded:
//
// RFX-4 Bug-1: legs were evaluated across the WHOLE Signals. If Config A had
// private-data + untrusted-ingest, and Config B (a different agent) had exfil,
// a false-positive RED was raised. Fix: evaluate per-ConfigFact — only fire
// when one agent has all three.
//
// RFX-4 Bug-2: the exfil leg used McpServerNames (keyed on ".command") so a
// command-less remote HTTP/SSE server (only url/type keys) was invisible.
// Fix: enumerate exfil via mcpAllServerNames (any mcpServers.<name>.* key).

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/aiagent"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX4_AGT002_PipelineParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "AGT002")

	t.Run("full trifecta in one config fires (command-based slack MCP)", func(t *testing.T) {
		// All three legs in one openclaw config — must fire.
		// Fixture: fs.workspaceOnly=false + browser.enabled=true + slack command MCP.
		// The Slack bot token in env will be redacted to "[secret]" by the pipeline
		// (env.* path is a credential field). The structural keys (command, args.*,
		// type, url) are passed verbatim so the check can read them.
		fixturePath := filepath.Join("testdata", "rfx4_agt002_full_trifecta.json")
		fact := collectConfigInternal(fixturePath, parseOpenclawConfig)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — fixture parse failed; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{
			Collector: &model.Signals{Configs: []model.ConfigFact{fact}},
		}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "AGT002" && f.IsFail() {
				return // expected critical failure found
			}
		}
		t.Fatalf("RFX-4: want AGT002 firing for full trifecta in one config; got %+v\nRedacted: %v", findings, fact.Values)
	})

	t.Run("remote command-less slack MCP (url+type only) fires exfil leg", func(t *testing.T) {
		// RFX-4 Bug-2 regression: the exfil leg must be satisfied by a remote Slack
		// server that has NO command key — only type=http and url pointing to Slack.
		// Before the fix, McpServerNames (keyed on ".command") skipped this server.
		fixturePath := filepath.Join("testdata", "rfx4_agt002_remote_slack_exfil.json")
		fact := collectConfigInternal(fixturePath, parseOpenclawConfig)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — fixture parse failed; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{
			Collector: &model.Signals{Configs: []model.ConfigFact{fact}},
		}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "AGT002" && f.IsFail() {
				return // expected critical failure found
			}
		}
		t.Fatalf("RFX-4: want AGT002 firing for remote command-less Slack MCP trifecta; got %+v\nRedacted: %v", findings, fact.Values)
	})

	t.Run("legs split across two distinct configs do NOT fire", func(t *testing.T) {
		// RFX-4 Bug-1 regression: private-data + untrusted-ingest in Config A,
		// exfil in Config B — must NOT fire because no single agent has all three.
		// Before the fix, legs were ORed across all Configs, producing a false RED.
		fixtureA := filepath.Join("testdata", "rfx4_agt002_split_legs_config_a.json")
		fixtureB := filepath.Join("testdata", "rfx4_agt002_split_legs_config_b.json")
		factA := collectConfigInternal(fixtureA, parseOpenclawConfig)
		factB := collectConfigInternal(fixtureB, parseOpenclawConfig)
		if !factA.SchemaKnown {
			t.Fatalf("factA SchemaKnown=false — fixture parse failed; values: %v", factA.Values)
		}
		if !factB.SchemaKnown {
			t.Fatalf("factB SchemaKnown=false — fixture parse failed; values: %v", factB.Values)
		}
		ctx := &model.ScanContext{
			Collector: &model.Signals{Configs: []model.ConfigFact{factA, factB}},
		}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "AGT002" && f.IsFail() {
				t.Errorf("RFX-4: AGT002 must NOT fire when legs are split across two distinct configs; got %+v\nFactA: %v\nFactB: %v", f, factA.Values, factB.Values)
			}
		}
	})

	t.Run("missing untrusted-ingest leg does NOT fire", func(t *testing.T) {
		// Config A has private-data + exfil but no browser/web-search/web MCP.
		// Must not fire — the ingest leg is absent so prompt injection cannot occur.
		// Re-using the split config A fixture (private-data + browser + no exfil MCP)
		// but setting browser.enabled to not-true is complex to do inline; instead
		// use the exfil-only config B (no browser, no private-data) to confirm
		// a partial config never fires alone.
		fixtureB := filepath.Join("testdata", "rfx4_agt002_split_legs_config_b.json")
		factB := collectConfigInternal(fixtureB, parseOpenclawConfig)
		if !factB.SchemaKnown {
			t.Fatalf("factB SchemaKnown=false — fixture parse failed; values: %v", factB.Values)
		}
		ctx := &model.ScanContext{
			Collector: &model.Signals{Configs: []model.ConfigFact{factB}},
		}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "AGT002" && f.IsFail() {
				t.Errorf("RFX-4: AGT002 must NOT fire when untrusted-ingest leg absent; got %+v\nFactB: %v", f, factB.Values)
			}
		}
	})
}
