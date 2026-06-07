package collect

// TestRFX8_MCP002_PipelineParserFed is the PARSER-FED regression test for
// RFX-8 / MCP002.
//
// MCP002 flags a secret-bearing MCP config file whose on-disk mode has any
// group or other bits set (0077). The previous code used n > 0o600, which
// incorrectly flagged owner-execute-only mode 0700.
//
// The mode comes from collectConfigInternal (config.go:76):
//
//	fact.Mode = fmt.Sprintf("%04o", linfo.Mode().Perm())
//
// A genuine parser-fed test must:
//  1. Write the fixture content to a real temp file.
//  2. chmod the file to the desired permission.
//  3. Call collectConfigInternal so that the REAL lstat path produces fact.Mode.
//  4. Feed the resulting ConfigFact to mcp002.Run() and assert the finding.
//
// Synthetic-signal tests (pre-populating ConfigFact.Mode directly) cannot catch
// a regression in the lstat->Sprintf formatting path; this test can.

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/aiagent"
	_ "github.com/jwlamon/keelix/internal/checks/mcp"
	"github.com/jwlamon/keelix/internal/model"
)

// TestRFX8_MCP002_PipelineParserFed verifies the full parse->stat->redact->check
// pipeline for MCP002 mode checking. It exercises the real lstat path in
// collectConfigInternal and confirms that:
//
//   - 0700 (owner-only rwx) on a secret-bearing config must NOT flag (RFX-8 fix)
//   - 0600 (owner-only rw)  on a secret-bearing config must NOT flag
//   - 0644 (group/other read) on a secret-bearing config MUST flag
//   - 0660 (group read+write) on a secret-bearing config MUST flag
func TestRFX8_MCP002_PipelineParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "MCP002")

	// Read the fixture content once; we'll write it to a fresh temp file for
	// each sub-test so we can chmod to the desired permission.
	fixtureContent, err := os.ReadFile(filepath.Join("testdata", "rfx8_mcp002_secret.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	tests := []struct {
		name     string
		mode     os.FileMode
		wantFail bool
	}{
		{
			name:     "RFX-8 mode 0700 (owner-only rwx) on secret-bearing config must NOT flag",
			mode:     0o700,
			wantFail: false,
		},
		{
			name:     "RFX-8 mode 0600 (owner-only rw) on secret-bearing config must NOT flag",
			mode:     0o600,
			wantFail: false,
		},
		{
			name:     "RFX-8 mode 0644 (group/other read) on secret-bearing config MUST flag",
			mode:     0o644,
			wantFail: true,
		},
		{
			name:     "RFX-8 mode 0660 (group read+write) on secret-bearing config MUST flag",
			mode:     0o660,
			wantFail: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Write fixture to a real temp file so lstat produces a real Mode.
			dir := t.TempDir()
			tmpPath := filepath.Join(dir, "mcp.json")
			if err := os.WriteFile(tmpPath, fixtureContent, 0o600); err != nil {
				t.Fatalf("write temp fixture: %v", err)
			}
			// chmod to the desired permission so collectConfigInternal sees it.
			if err := os.Chmod(tmpPath, tt.mode); err != nil {
				t.Fatalf("chmod %04o: %v", tt.mode, err)
			}

			// Run the REAL parse->stat->redact pipeline.
			// collectConfigInternal bypasses the production allowlist gate so
			// temp paths are accepted; it lstats tmpPath and encodes the real
			// on-disk permission into ConfigFact.Mode.
			fact := collectConfigInternal(tmpPath, parseCursorMCP)
			if !fact.SchemaKnown {
				t.Fatalf("collectConfigInternal: SchemaKnown=false — fixture parse failed\nValues: %v", fact.Values)
			}
			if fact.Mode == "" {
				t.Fatalf("collectConfigInternal: fact.Mode is empty — lstat path not exercised")
			}

			// Feed the redacted ConfigFact to the check.
			ctx := &model.ScanContext{
				Collector: &model.Signals{
					Configs: []model.ConfigFact{fact},
				},
			}
			findings := c.Run(ctx)

			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Errorf("mode %04o: wantFail=%v got hasFail=%v\nfact.Mode=%q values=%v\nfindings=%+v",
					tt.mode, tt.wantFail, hasFail, fact.Mode, fact.Values, findings)
			}
		})
	}
}

// TestRFX8_AGT004_PipelineParserFed is the PARSER-FED regression test for
// RFX-8 / AGT004.
//
// AGT004 flags agent credential files whose on-disk mode has any group or other
// bits set (0077). The previous code used n > 0o600, which incorrectly flagged
// 0700 (owner-execute bit set, but no group/other access).
//
// The mode comes from statFiles (files.go:176) / buildFileFact (files.go:153):
//
//	fact.Mode = fmt.Sprintf("%04o", fi.Mode().Perm())
//
// A genuine parser-fed test must:
//  1. Create a real temp file at a path that matches isAgentTokenFile.
//  2. chmod the file to the desired permission.
//  3. Call statFiles so the REAL lstat->Sprintf path produces FileFact.Mode.
//  4. Feed the resulting FileFact to agt004.Run() and assert the finding.
//
// Synthetic-signal tests (pre-populating FileFact.Mode directly) cannot catch
// a regression in the lstat->Sprintf formatting path; this test can.
func TestRFX8_AGT004_PipelineParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "AGT004")

	tests := []struct {
		name     string
		mode     os.FileMode
		wantFail bool
	}{
		{
			name:     "RFX-8 mode 0700 (owner-only rwx) must NOT flag",
			mode:     0o700,
			wantFail: false,
		},
		{
			name:     "RFX-8 mode 0600 (owner-only rw) must NOT flag",
			mode:     0o600,
			wantFail: false,
		},
		{
			name:     "RFX-8 mode 0644 (group/other read) MUST flag",
			mode:     0o644,
			wantFail: true,
		},
		{
			name:     "RFX-8 mode 0660 (group read+write) MUST flag",
			mode:     0o660,
			wantFail: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp directory tree that looks like ~/.openclaw/ so that
			// isAgentTokenFile matches the path (checks for ".openclaw/openclaw.json").
			home := t.TempDir()
			dir := filepath.Join(home, ".openclaw")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir .openclaw: %v", err)
			}
			// The path substring ".openclaw/openclaw.json" must be present.
			credPath := filepath.Join(dir, "openclaw.json")
			if err := os.WriteFile(credPath, []byte(`{"token":"dummy"}`), 0o600); err != nil {
				t.Fatalf("write cred file: %v", err)
			}
			// chmod to the desired permission so statFiles sees the real mode.
			if err := os.Chmod(credPath, tt.mode); err != nil {
				t.Fatalf("chmod %04o: %v", tt.mode, err)
			}

			// Run the REAL lstat->fmt.Sprintf path via statFiles.
			// statFiles calls os.Lstat and encodes Mode via buildFileFact.
			facts := statFiles([]string{credPath})
			if len(facts) != 1 {
				t.Fatalf("statFiles: expected 1 fact, got %d", len(facts))
			}
			ff := facts[0]
			if !ff.Exists {
				t.Fatalf("statFiles: Exists=false for %s", credPath)
			}
			if ff.Mode == "" {
				t.Fatalf("statFiles: Mode is empty — lstat path not exercised")
			}

			// Feed the real FileFact to the check.
			ctx := &model.ScanContext{
				Collector: &model.Signals{
					Files: []model.FileFact{ff},
				},
			}
			findings := c.Run(ctx)

			hasFail := false
			for _, f := range findings {
				if f.CheckID == "AGT004" && f.IsFail() {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Errorf("mode %04o: wantFail=%v got hasFail=%v\nff.Mode=%q\nfindings=%+v",
					tt.mode, tt.wantFail, hasFail, ff.Mode, findings)
			}
		})
	}
}
