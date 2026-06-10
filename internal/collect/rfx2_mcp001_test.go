package collect

// TestRFX2_MCP001_PipelineParserFed is the PARSER-FED regression test for RFX-2.
// It calls collectConfigInternal on real fixture files (raw credential values) and
// then feeds the resulting model.ConfigFact — after the full parse->redact pipeline
// has run — to mcp001.Run() via the registered model.Check interface.
//
// This is the test that the spec meta-rule mandates: it exercises the complete
//   parse -> redact -> check
// pipeline end-to-end, guarding against bugs that synthetic-signal tests (which
// pre-populate ConfigFact.Values with "[secret]"/"[keychain-ref]" directly) can
// never catch.
//
// Fixtures live in testdata/ and contain RAW credential values (e.g. real-shaped
// API keys, keychain: URIs, Bearer tokens). The collect pipeline is responsible
// for transforming these into "[secret]" or "[keychain-ref]" before the check
// sees them — this test verifies that transformation is correct AND that the
// check responds correctly to those transformed values.
//
// The specific bug guarded by this test (RFX-2b): before the fix, the shared
// mcpServerNames helper only enumerated servers that had a ".command" key, so a
// command-less remote server (type/url/headers only) was silently skipped —
// no MCP001 finding was ever emitted. Synthetic tests pre-populating Values with
// "[secret]" could not catch this because they bypass parseMCPJSON entirely.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/mcp"
	"github.com/jakelamon/keelix/internal/model"
)

// findRegisteredCheck returns the registered model.Check with the given ID,
// or fails the test if it is not registered.
func findRegisteredCheck(t *testing.T, id string) model.Check {
	t.Helper()
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %s not registered (blank-import checks/mcp missing?)", id)
	return nil
}

func TestRFX2_MCP001_PipelineParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "MCP001")

	tests := []struct {
		name     string
		fixture  string // filename under testdata/ (raw, pre-redaction values)
		parser   func([]byte) (map[string]string, string, bool)
		wantFail bool // want at least one Critical non-passing finding
		wantPass bool // want at least one passing finding (no fail)
	}{
		// RFX-2(a) POSITIVE CONTROL — keychain-ref values must NOT fire MCP001.
		// Fixture: two env vars holding keychain: and op:// references.
		// collect pipeline emits "[keychain-ref]" for each.
		// MCP001 must produce a passing finding (no Critical fail).
		{
			name:     "RFX-2(a) keychain-ref env vars pass (positive control)",
			fixture:  "rfx2_keychain_ref.json",
			parser:   parseCursorMCP,
			wantPass: true,
		},
		// RFX-2(a) INLINED SECRET — plaintext API key must fire MCP001.
		// Fixture: env.API_KEY holds a high-entropy raw key string.
		// collect pipeline emits "[secret]" (key name contains "key").
		// MCP001 must produce a Critical failing finding.
		{
			name:     "RFX-2(a) plaintext API key in env fires MCP001",
			fixture:  "rfx2_secret_env.json",
			parser:   parseCursorMCP,
			wantFail: true,
		},
		// RFX-2(b) COMMAND-LESS REMOTE SERVER — the exact bug synthetic tests hid.
		// Fixture: a server with NO "command" key — only type/url/headers.
		// Before the RFX-2 fix, mcp001ServerNames only scanned keys ending in
		// ".command", so this server was invisible and no finding was emitted.
		// After the fix, mcp001ServerNames scans ALL mcpServers.* keys so the
		// server is found via its type/url/headers keys instead.
		// collect pipeline emits "[secret]" for Authorization: Bearer <token>.
		// MCP001 must produce a Critical failing finding.
		{
			name:     "RFX-2(b) remote http server url-only with secret header fires MCP001",
			fixture:  "rfx2_remote_secret_header.json",
			parser:   parseCursorMCP,
			wantFail: true,
		},
		// RFX-2(b)+(a) COMMAND-LESS REMOTE SERVER, KEYCHAIN HEADER — must pass.
		// Fixture: a server with NO "command" key — only type/url/headers — where
		// the Authorization header holds a keychain: reference.
		// collect pipeline emits "[keychain-ref]".
		// MCP001 must pass (not fire). Ensures the RFX-2(b) fix doesn't introduce
		// false positives on properly secured remote servers.
		{
			name:     "RFX-2(b)+(a) remote http server url-only with keychain header passes",
			fixture:  "rfx2_remote_keychain_header.json",
			parser:   parseCursorMCP,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run the REAL parse->redact pipeline. collectConfigInternal bypasses
			// the production allowlist gate so testdata paths are accepted.
			fixturePath := filepath.Join("testdata", tt.fixture)
			fact := collectConfigInternal(fixturePath, tt.parser)
			if !fact.SchemaKnown {
				t.Fatalf("collectConfigInternal: SchemaKnown=false — fixture parse failed for %s\n"+
					"Values: %v", tt.fixture, fact.Values)
			}

			// Feed the redacted ConfigFact to the check.
			ctx := &model.ScanContext{
				Collector: &model.Signals{
					Configs: []model.ConfigFact{fact},
				},
			}
			findings := c.Run(ctx)

			if tt.wantFail {
				for _, f := range findings {
					if !f.Passed && f.Severity == model.SeverityCritical {
						return // found expected critical failure
					}
				}
				t.Fatalf("want Critical fail finding from MCP001; got %+v\n"+
					"Redacted values: %v", findings, fact.Values)
			}
			if tt.wantPass {
				for _, f := range findings {
					if f.Passed {
						return // found expected pass
					}
				}
				t.Fatalf("want pass finding from MCP001; got %+v\n"+
					"Redacted values: %v", findings, fact.Values)
			}
		})
	}
}
