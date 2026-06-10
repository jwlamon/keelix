package collect

// TestRFX6_HST023_ParserFed is the MANDATORY PARSER-FED regression test for
// RFX-6(a): HST023 mode bitmask reconciled to spec (0o077: flag when group OR
// other can read/write/execute /etc/shadow).
//
// File-permission facts are produced by statFiles (files.go) which calls
// os.Lstat and encodes the mode via fmt.Sprintf("%04o", fi.Mode().Perm()).
// A genuine parser-fed test must:
//
//  1. Create a real temp file at a path that looks like /etc/shadow to the check
//     (i.e. the check only inspects the Path field, so any path that matches
//     "/etc/shadow" in FileFact.Path works — we use a temp file and override the
//     Path after the stat so the check can find it).
//  2. chmod the file to the test permission.
//  3. Call statFiles so the REAL lstat→Sprintf path produces FileFact.Mode.
//  4. Override FileFact.Path to "/etc/shadow" (the check looks up by path, not by
//     disk location) and feed the fact to HST023.Run().
//
// This pattern mirrors TestRFX8_AGT004_PipelineParserFed; it guards against any
// future regression in the lstat→Sprintf→ParseUint→bitmask chain.

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/host"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX6_HST023_ParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "HST023")

	tests := []struct {
		name     string
		mode     os.FileMode
		wantFail bool
	}{
		{
			// 0600 (rw-------): root-only, no group or world bits → passes.
			name:     "mode_0600_root_only_passes",
			mode:     0o600,
			wantFail: false,
		},
		{
			// 0000: no bits set at all → passes (0o000 & 0o077 == 0).
			name:     "mode_0000_no_perms_passes",
			mode:     0o000,
			wantFail: false,
		},
		{
			// 0640 (rw-r-----): group-read bit set → fires under 0o077 mask.
			// Common on Debian/Ubuntu with root:shadow, but spec requires root-only.
			name:     "mode_0640_group_read_fires",
			mode:     0o640,
			wantFail: true,
		},
		{
			// 0644 (rw-r--r--): world-read bit set → fires.
			name:     "mode_0644_world_read_fires",
			mode:     0o644,
			wantFail: true,
		},
		{
			// 0620 (rw--w----): group-write bit set → fires.
			name:     "mode_0620_group_write_fires",
			mode:     0o620,
			wantFail: true,
		},
		{
			// 0777: all bits set → fires.
			name:     "mode_0777_all_bits_fires",
			mode:     0o777,
			wantFail: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp file and chmod it to the desired mode so that
			// statFiles sees the real permission via lstat.
			tmp := t.TempDir()
			shadowPath := tmp + "/shadow_test"
			if err := os.WriteFile(shadowPath, []byte("root:*:19000:0:99999:7:::\n"), 0o600); err != nil {
				t.Fatalf("write temp shadow: %v", err)
			}
			if err := os.Chmod(shadowPath, tt.mode); err != nil {
				t.Fatalf("chmod %04o: %v", tt.mode, err)
			}

			// Run the REAL lstat→Sprintf path via statFiles (files.go).
			facts := statFiles([]string{shadowPath})
			if len(facts) != 1 {
				t.Fatalf("statFiles: expected 1 fact, got %d", len(facts))
			}
			ff := facts[0]
			if !ff.Exists {
				t.Fatalf("statFiles: Exists=false for temp file — lstat failed")
			}
			// Override Path so the check's fileByPath lookup for "/etc/shadow" matches.
			ff.Path = "/etc/shadow"

			ctx := &model.ScanContext{
				Collector: &model.Signals{
					Platform: model.Platform{OS: "linux"},
					Files:    []model.FileFact{ff},
				},
			}
			findings := c.Run(ctx)

			hasFail := false
			for _, f := range findings {
				if f.CheckID == "HST023" && f.IsFail() {
					hasFail = true
					break
				}
			}
			if hasFail != tt.wantFail {
				t.Fatalf("RFX-6 HST023 mode=%04o: hasFail=%v wantFail=%v\n"+
					"FileFact.Mode=%q findings=%+v",
					tt.mode, hasFail, tt.wantFail, ff.Mode, findings)
			}
		})
	}
}

// TestRFX6_SudoersDFacts_ParserFed is the MANDATORY PARSER-FED regression test
// for RFX-6(c): /etc/sudoers.d/* fragment content must be parsed and merged so
// that HST020 can detect NOPASSWD rules in drop-in files.
//
// CRITICAL TWO-FACT SCENARIO: On every standard Linux deployment /etc/sudoers
// exists and is parsed into Configs[0], and the merged /etc/sudoers.d result
// becomes Configs[1].  If /etc/sudoers is clean (nopasswd.present="false") but
// a sudoers.d fragment has NOPASSWD, a naive first-match implementation of
// HST020 reads only Configs[0] and returns a false pass.
//
// This test injects both facts in the correct order (clean /etc/sudoers first,
// dirty sudoers.d second) and asserts that HST020 still fires.  Without the
// two-fact injection, the test would pass even with the broken first-match
// implementation, making it an incomplete guard.
//
// Parser chain exercised:
//  1. parseSudoers(sudoers_clean.txt)    → nopasswd.present="false"  (Configs[0])
//  2. parseSudoers(sudoers_d_clean.txt + sudoers_d_nopasswd.txt) → nopasswd.present="true" (Configs[1])
//  3. HST020.Run() iterates both facts and fires on the second one.
func TestRFX6_SudoersDFacts_ParserFed(t *testing.T) {
	hst020 := findRegisteredCheck(t, "HST020")

	// --- Fact 0: /etc/sudoers (clean — no NOPASSWD) ---
	mainSudoers := mustReadTestdata(t, "sudoers_clean.txt")
	mainVals, mainSchemaID, mainKnown := parseSudoers(mainSudoers)
	if !mainKnown {
		t.Fatalf("parseSudoers(sudoers_clean.txt): known=false")
	}
	if mainSchemaID != "accounts-sudoers" {
		t.Fatalf("parseSudoers(sudoers_clean.txt): schemaID=%q, want accounts-sudoers", mainSchemaID)
	}
	if mainVals["nopasswd.present"] != "false" {
		t.Fatalf("parseSudoers(sudoers_clean.txt): nopasswd.present=%q, want false — fixture must not contain NOPASSWD", mainVals["nopasswd.present"])
	}
	cleanFact := model.ConfigFact{
		Source:      filepath.Join("testdata", "sudoers_clean.txt"),
		SchemaID:    mainSchemaID,
		SchemaKnown: true,
		Values:      mainVals,
	}

	// --- Fact 1: /etc/sudoers.d (merged fragments — contains NOPASSWD) ---
	// Concatenate the two drop-in fragments exactly as collectSudoersDFacts does.
	fragClean := mustReadTestdata(t, "sudoers_d_clean.txt")
	fragNopasswd := mustReadTestdata(t, "sudoers_d_nopasswd.txt")
	merged := make([]byte, 0, len(fragClean)+1+len(fragNopasswd))
	merged = append(merged, fragClean...)
	merged = append(merged, '\n')
	merged = append(merged, fragNopasswd...)

	fragVals, fragSchemaID, fragKnown := parseSudoers(merged)
	if !fragKnown {
		t.Fatalf("parseSudoers(merged sudoers.d): known=false — NOPASSWD not detected")
	}
	if fragSchemaID != "accounts-sudoers" {
		t.Fatalf("parseSudoers(merged sudoers.d): schemaID=%q, want accounts-sudoers", fragSchemaID)
	}
	if fragVals["nopasswd.present"] != "true" {
		t.Fatalf("parseSudoers(merged sudoers.d): nopasswd.present=%q, want true\nValues: %v", fragVals["nopasswd.present"], fragVals)
	}
	sudoersDFact := model.ConfigFact{
		Source:      filepath.Join("testdata", "sudoers_d_nopasswd.txt"),
		SchemaID:    fragSchemaID,
		SchemaKnown: true,
		Values:      fragVals,
	}

	// --- Feed BOTH facts to HST020 in the real-world order (clean first) ---
	// This is the critical two-fact scenario: Configs[0] is clean, Configs[1] is dirty.
	// A first-match implementation would silently pass; the correct fix iterates all facts.
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{cleanFact, sudoersDFact},
		},
	}

	findings := hst020.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "HST020" && f.IsFail() {
			return // correct: NOPASSWD in sudoers.d fragment detected despite clean /etc/sudoers
		}
	}
	t.Fatalf("RFX-6 two-fact scenario: HST020 must fire when /etc/sudoers is clean but sudoers.d has NOPASSWD;\ngot findings=%+v\ncleanFact.Values=%v\nsudoersDFact.Values=%v",
		findings, mainVals, fragVals)
}
