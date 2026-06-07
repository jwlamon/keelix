package collect

// TestRFX3_MCP003_PipelineParserFed and TestRFX3_MCP006_PipelineParserFed are
// the PARSER-FED regression tests mandated by the spec meta-rule for RFX-3.
//
// Each test calls collectConfigInternal on a real fixture file (raw, pre-redaction
// values) and feeds the resulting model.ConfigFact — after the full
//
//	parse -> redact -> check
//
// pipeline has run — to the relevant check via the registered model.Check interface.
//
// This is the pattern that synthetic-signal tests (which pre-populate
// ConfigFact.Values directly with the post-redaction markers) CANNOT exercise,
// because they bypass the parser entirely and can therefore never catch bugs in
// argument parsing, flattening, or key-path-aware redaction.
//
// Fixture files live in testdata/ and contain RAW values (real-shaped package
// specs, npm scoped-package names, github: refs). The collect pipeline emits
// args.* values VERBATIM (structural fields, not credential paths) — this test
// verifies that invariant AND that the check logic responds correctly.
//
// MCP003 guards: pinned-version detection must fire on "@scope/pkg" (no pin)
// and must NOT fire on "@scope/pkg@1.0.8" (pin present).
//
// MCP006 guards: provenance detection must fire on "@scope/unknown-pkg" (unverified
// npm org) and "github:rando/x" (direct repo ref), and must NOT fire on
// "@modelcontextprotocol/server-filesystem" (verified org).

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/mcp"
	"github.com/jwlamon/keelix/internal/model"
)

func TestRFX3_MCP003_PipelineParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "MCP003")

	tests := []struct {
		name     string
		fixture  string // filename under testdata/ (raw, pre-redaction values)
		parser   func([]byte) (map[string]string, string, bool)
		wantFail bool // want at least one Warning non-passing finding
		wantPass bool // want at least one passing finding
	}{
		// Unpinned "@upstash/context7-mcp" — no "@<ver>" suffix anywhere in args.
		// collect pipeline emits args.* values verbatim (structural fields).
		// MCP003 must detect the missing version pin and emit a Warning finding.
		{
			name:     "RFX-3 unpinned @upstash/context7-mcp fires MCP003",
			fixture:  "rfx3_mcp003_unpinned.json",
			parser:   parseCursorMCP,
			wantFail: true,
		},
		// Pinned "@upstash/context7-mcp@1.0.8" — "@1.0.8" suffix present after position 0.
		// collect pipeline emits the arg verbatim.
		// MCP003 must recognise the pin and emit a passing finding (no Warning).
		{
			name:     "RFX-3 pinned @upstash/context7-mcp@1.0.8 passes MCP003",
			fixture:  "rfx3_mcp003_pinned.json",
			parser:   parseCursorMCP,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixturePath := filepath.Join("testdata", tt.fixture)
			fact := collectConfigInternal(fixturePath, tt.parser)
			if !fact.SchemaKnown {
				t.Fatalf("collectConfigInternal: SchemaKnown=false — fixture parse failed for %s\nValues: %v",
					tt.fixture, fact.Values)
			}

			ctx := &model.ScanContext{
				Collector: &model.Signals{
					Configs: []model.ConfigFact{fact},
				},
			}
			findings := c.Run(ctx)

			if tt.wantFail {
				for _, f := range findings {
					if !f.Passed && f.Severity == model.SeverityWarning {
						return
					}
				}
				t.Fatalf("want Warning fail finding from MCP003; got %+v\nRedacted values: %v",
					findings, fact.Values)
			}
			if tt.wantPass {
				for _, f := range findings {
					if f.Passed {
						return
					}
				}
				t.Fatalf("want pass finding from MCP003; got %+v\nRedacted values: %v",
					findings, fact.Values)
			}
		})
	}
}

func TestRFX3_MCP006_PipelineParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "MCP006")

	tests := []struct {
		name     string
		fixture  string // filename under testdata/ (raw, pre-redaction values)
		parser   func([]byte) (map[string]string, string, bool)
		wantFail bool // want at least one Warning non-passing finding
		wantPass bool // want at least one passing finding
	}{
		// Unverified npm org scope "@scope/unknown-pkg".
		// collect pipeline emits the arg verbatim (structural field).
		// MCP006 must flag "@scope" as not in verifiedMCPOrgs.
		{
			name:     "RFX-3 @scope/unknown-pkg fires MCP006 (unverified org)",
			fixture:  "rfx3_mcp006_unverified.json",
			parser:   parseCursorMCP,
			wantFail: true,
		},
		// Direct GitHub repo reference "github:randomuser/my-mcp-server".
		// collect pipeline emits the arg verbatim.
		// MCP006 must flag the "github:" prefix as an individual-repo reference.
		{
			name:     "RFX-3 github:randomuser/my-mcp-server fires MCP006 (direct-repo ref)",
			fixture:  "rfx3_mcp006_github.json",
			parser:   parseCursorMCP,
			wantFail: true,
		},
		// Verified org "@modelcontextprotocol/server-filesystem@1.0.0".
		// collect pipeline emits the arg verbatim.
		// MCP006 must NOT flag this — "@modelcontextprotocol/" is in verifiedMCPOrgs.
		{
			name:     "RFX-3 @modelcontextprotocol/server-filesystem passes MCP006 (verified org)",
			fixture:  "rfx3_mcp006_verified.json",
			parser:   parseCursorMCP,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixturePath := filepath.Join("testdata", tt.fixture)
			fact := collectConfigInternal(fixturePath, tt.parser)
			if !fact.SchemaKnown {
				t.Fatalf("collectConfigInternal: SchemaKnown=false — fixture parse failed for %s\nValues: %v",
					tt.fixture, fact.Values)
			}

			ctx := &model.ScanContext{
				Collector: &model.Signals{
					Configs: []model.ConfigFact{fact},
				},
			}
			findings := c.Run(ctx)

			if tt.wantFail {
				for _, f := range findings {
					if !f.Passed && f.Severity == model.SeverityWarning {
						return
					}
				}
				t.Fatalf("want Warning fail finding from MCP006; got %+v\nRedacted values: %v",
					findings, fact.Values)
			}
			if tt.wantPass {
				for _, f := range findings {
					if f.Passed {
						return
					}
				}
				t.Fatalf("want pass finding from MCP006; got %+v\nRedacted values: %v",
					findings, fact.Values)
			}
		})
	}
}
