package aiagent_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/collect"
	"github.com/jakelamon/keelix/internal/model"
)

func TestAGT005_BackupFile(t *testing.T) {
	c := findCheck(t, "AGT005")
	sigs := &model.Signals{
		Files: []model.FileFact{
			{Path: "/home/user/.openclaw/openclaw.json.bak", Exists: true, Mode: "0600"},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT005" && f.IsFail() {
			found = true
			if f.Confidence != model.ConfidenceLow {
				t.Errorf("AGT005: want ConfidenceLow, got %v", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("AGT005: want failing finding for .bak file")
	}
}

func TestAGT005_NoBackup_Pass(t *testing.T) {
	c := findCheck(t, "AGT005")
	sigs := &model.Signals{
		Files: []model.FileFact{
			{Path: "/home/user/.openclaw/openclaw.json", Exists: true, Mode: "0600"},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT005" && f.IsFail() {
			t.Errorf("AGT005: no backup file should pass, got %+v", f)
		}
	}
}

func TestAGT005_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT005")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT005: want NotAssessed, got %+v", findings)
	}
}

// TestAGT005_CollectorFed_BackupSprawl is the PARSER-FED regression case for
// RFX-5. It exercises the full collect.Collect pipeline against a temp HOME
// containing a ~/.claude.json.bak file, then feeds the resulting *model.Signals
// directly to AGT005. This test cannot be fooled by synthetic signal injection
// and guards against regressions where collectFiles skips backup siblings.
func TestAGT005_CollectorFed_BackupSprawl(t *testing.T) {
	home := t.TempDir()

	// Create ~/.claude.json.bak — a backup of the canonical agent config.
	bakPath := filepath.Join(home, ".claude.json.bak")
	if err := os.WriteFile(bakPath, []byte(`{"backup":true}`), 0o600); err != nil {
		t.Fatalf("write bak: %v", err)
	}

	collect.RebuildAllowlistForHome(home)
	t.Cleanup(collect.RebuildAllowlistForDefaultHome)

	sigs, err := collect.Collect(collect.Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	c := findCheck(t, "AGT005")
	ctx := &model.ScanContext{Collector: sigs}
	findings := c.Run(ctx)

	for _, f := range findings {
		if f.CheckID == "AGT005" && f.IsFail() {
			return // expected: backup sprawl detected
		}
	}
	t.Fatalf("RFX-5: AGT005 did not fire for backup file %q.\nFindings: %+v\nFiles: %v",
		bakPath, findings, sigs.Files)
}
