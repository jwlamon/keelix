package collect

// TestRFX1_HST020_021_022_ParserFed are the MANDATORY PARSER-FED regression
// tests for RFX-1: HST020/021/022 were dead because the checks called
// configBySchema with the wrong SchemaIDs ("sudoers", "passwd", "shadow")
// while the real parsers emit "accounts-sudoers", "accounts-passwd",
// "accounts-shadow". All three checks always returned NotAssessed on real
// hosts — NOPASSWD sudo, duplicate UID-0, and empty-password accounts were
// never detected.
//
// Each test runs the real parser (parseSudoers/parsePasswd/parseShadow) over
// the committed testdata/{sudoers.txt,passwd.txt,shadow.txt} fixtures, builds
// a ScanContext whose Collector.Configs holds the produced ConfigFact, then
// runs the check and asserts it FIRES. This is the pattern that the spec
// meta-rule mandates: real parser → ConfigFact → check.Run() — no synthetic
// model.Signals with hand-written SchemaIDs.

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

// TestRFX1_HST020_ParserFed verifies that HST020 fires on a sudoers file that
// contains a NOPASSWD directive. The real parseSudoers parser is called over
// testdata/sudoers.txt; the resulting ConfigFact is fed directly to the check.
func TestRFX1_HST020_ParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "HST020")

	b := mustReadTestdata(t, "sudoers.txt")
	vals, schemaID, known := parseSudoers(b)
	if !known {
		t.Fatalf("parseSudoers: known=false on sudoers.txt fixture")
	}
	if schemaID != "accounts-sudoers" {
		t.Fatalf("parseSudoers: schemaID=%q, want accounts-sudoers", schemaID)
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sudoers.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}

	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "HST020" && f.IsFail() {
			return // expected: NOPASSWD rule detected
		}
	}
	t.Fatalf("RFX-1: HST020 must fire for NOPASSWD in sudoers.txt; got %+v\nValues: %v", findings, vals)
}

// TestRFX1_HST021_ParserFed verifies that HST021 fires when /etc/passwd
// contains two UID-0 accounts (root and toor in the fixture). The real
// parsePasswd parser is called over testdata/passwd.txt.
func TestRFX1_HST021_ParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "HST021")

	b := mustReadTestdata(t, "passwd.txt")
	vals, schemaID, known := parsePasswd(b)
	if !known {
		t.Fatalf("parsePasswd: known=false on passwd.txt fixture")
	}
	if schemaID != "accounts-passwd" {
		t.Fatalf("parsePasswd: schemaID=%q, want accounts-passwd", schemaID)
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "passwd.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}

	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "HST021" && f.IsFail() {
			return // expected: multiple UID-0 accounts detected
		}
	}
	t.Fatalf("RFX-1: HST021 must fire for duplicate UID-0 in passwd.txt; got %+v\nValues: %v", findings, vals)
}

// TestRFX1_HST022_ParserFed verifies that HST022 fires when /etc/shadow
// contains an account with an empty password field (alice in the fixture).
// The real parseShadow parser is called over testdata/shadow.txt.
func TestRFX1_HST022_ParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "HST022")

	b := mustReadTestdata(t, "shadow.txt")
	vals, schemaID, known := parseShadow(b)
	if !known {
		t.Fatalf("parseShadow: known=false on shadow.txt fixture")
	}
	if schemaID != "accounts-shadow" {
		t.Fatalf("parseShadow: schemaID=%q, want accounts-shadow", schemaID)
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "shadow.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}

	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "HST022" && f.IsFail() {
			return // expected: empty-password account detected
		}
	}
	t.Fatalf("RFX-1: HST022 must fire for empty-password account in shadow.txt; got %+v\nValues: %v", findings, vals)
}
