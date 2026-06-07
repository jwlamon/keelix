package aiagent_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/checks/aiagent"
	"github.com/jwlamon/keelix/internal/model"
)

func TestNotAssessed_SetsStatus(t *testing.T) {
	// catalog entry for AGT001 must exist (added in SLICE-B); skip compile-time
	// if not present by calling through the exported helper.
	f := aiagent.NotAssessed("AGT001")
	if f.Status != model.StatusNotAssessed {
		t.Errorf("want StatusNotAssessed, got %v", f.Status)
	}
	if f.CheckID != "AGT001" {
		t.Errorf("want CheckID AGT001, got %q", f.CheckID)
	}
}

func TestConfigBySchema_Found(t *testing.T) {
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{SchemaID: "openclaw-config", SchemaKnown: true, Values: map[string]string{"tools.exec.ask": "off"}},
			{SchemaID: "claude-code-settings", SchemaKnown: true, Values: map[string]string{"defaultMode": "bypassPermissions"}},
		},
	}
	got, ok := aiagent.ConfigBySchema(sigs, "openclaw-config")
	if !ok {
		t.Fatal("want found=true")
	}
	if got.Values["tools.exec.ask"] != "off" {
		t.Errorf("wrong value: %q", got.Values["tools.exec.ask"])
	}
}

func TestConfigBySchema_Missing(t *testing.T) {
	sigs := &model.Signals{}
	_, ok := aiagent.ConfigBySchema(sigs, "openclaw-config")
	if ok {
		t.Error("want found=false for empty Signals")
	}
}

func TestMcpServerNames_FromValues(t *testing.T) {
	vals := map[string]string{
		"mcpServers.filesystem.command": "npx",
		"mcpServers.slack.command":      "uvx",
		"mcpServers.slack.args.0":       "mcp-slack",
		"defaultMode":                   "default",
	}
	names := aiagent.McpServerNames(vals)
	if len(names) != 2 {
		t.Fatalf("want 2 names, got %v", names)
	}
	if names[0] != "filesystem" || names[1] != "slack" {
		t.Errorf("want [filesystem slack], got %v", names)
	}
}

// ---- AGT001 ----

func findCheck(t *testing.T, id string) model.Check {
	t.Helper()
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %s not registered", id)
	return nil
}

func makeCtxWithCollector(sigs *model.Signals) *model.ScanContext {
	return &model.ScanContext{Collector: sigs}
}
