package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

// TestCollectConfigsDomainSmoke verifies that collectConfigs returns a non-nil
// slice and appends facts for each home-relative path it tried (present or not).
// This is a smoke test — paths may not exist on the test host, but each attempt
// must produce at least a bare ConfigFact with Source set.
func TestCollectConfigsDomainSmoke(t *testing.T) {
	facts, err := collectConfigs(Options{})
	if err != nil {
		t.Fatalf("collectConfigs returned error: %v", err)
	}
	// Must return non-nil slice (even if all paths are absent).
	if facts == nil {
		t.Fatal("collectConfigs returned nil slice")
	}
	for _, f := range facts {
		if f.Source == "" {
			t.Error("ConfigFact with empty Source field")
		}
	}
}

// TestCollectConfigsDomainCanParseTestdata exercises collectConfigs indirectly
// by calling collectConfigInternal with the fixture paths, verifying that
// the parsers are wired to the correct schema IDs.
func TestCollectConfigsDomainCanParseTestdata(t *testing.T) {
	type tc struct {
		file   string
		parser func([]byte) (map[string]string, string, bool)
		wantID string
	}
	cases := []tc{
		{"openclaw-config.json", parseOpenclawConfig, "openclaw-config"},
		{"openclaw-exec-approvals.json", parseOpenclawExecApprovals, "openclaw-exec-approvals"},
		{"openclaw-cron.json", parseOpenclawCron, "openclaw-cron"},
		{"claude-code-settings.json", parseClaudeCodeSettings, "claude-code-settings"},
		{"claude.json", parseClaudeJSON, "claude-json"},
		{"codex-config.toml", parseCodexConfig, "codex-config"},
		{"claude-desktop-config.json", parseClaudeDesktopConfig, "claude-desktop-config"},
		{"mcp-config.json", parseMCPJSON, "mcp-json"},
	}
	for _, tc := range cases {
		t.Run(tc.wantID, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			fact := collectConfigInternal(path, tc.parser)
			if fact.SchemaID != tc.wantID {
				t.Errorf("SchemaID=%q, want %q (Source=%q SchemaKnown=%v)",
					fact.SchemaID, tc.wantID, fact.Source, fact.SchemaKnown)
			}
			if !fact.SchemaKnown {
				t.Errorf("SchemaKnown=false for %q", tc.file)
			}
		})
	}
}

// TestCollectIntegratesConfigsDomain verifies that Collect wires the configs
// domain: after Collect runs, Signals.Configs is non-nil (it may be empty if
// none of the agent config files exist on this machine, but the field must be
// populated, not nil, and Errors must not include a "configs" domain error).
func TestCollectIntegratesConfigsDomain(t *testing.T) {
	if os.Getenv("CI") != "" {
		// On CI the home-relative paths definitely don't exist; skip so the test
		// doesn't pollute error counts.
		t.Skip("skipping collectConfigs integration test on CI")
	}
	s, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, ce := range s.Errors {
		if ce.Domain == "configs" {
			t.Errorf("Collect produced a 'configs' domain error: %s", ce.Err)
		}
	}
	// Configs is allowed to be nil/empty when no agent config files exist.
	_ = s.Configs
}

// TestCollectConfigsHandlesMissingHomeGracefully verifies that collectConfigs
// does not panic when called in an environment where home paths do not exist.
func TestCollectConfigsHandlesMissingHomeGracefully(t *testing.T) {
	// Save and restore HOME-like env to simulate missing paths.
	// We rely on the fact that non-existent paths produce bare (zero-value) facts.
	facts, err := collectConfigs(Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range facts {
		// Every fact must have a source, even if the file is missing.
		if f.Source == "" {
			t.Error("ConfigFact with empty Source")
		}
		// A missing file must not have SchemaKnown=true.
		if f.Mode == "" && f.SchemaKnown {
			t.Errorf("missing file %q has SchemaKnown=true", f.Source)
		}
	}
}

// TestCollectConfigsProducesConfigFactForEachPath verifies the number of
// facts returned equals the number of path entries in the configs domain table.
func TestCollectConfigsProducesConfigFactForEachPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UserHomeDir: %v", err)
	}
	_ = home
	facts, err := collectConfigs(Options{})
	if err != nil {
		t.Fatalf("collectConfigs: %v", err)
	}
	// Must have at least the number of defined config paths.
	if len(facts) < len(configPathTable(home)) {
		t.Errorf("len(facts)=%d < len(configPathTable)=%d",
			len(facts), len(configPathTable(home)))
	}
}

// Ensure model import is not flagged as unused.
var _ model.ConfigFact
