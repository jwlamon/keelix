package aiagent_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestAGT004_TooOpenMode(t *testing.T) {
	c := findCheck(t, "AGT004")
	sigs := &model.Signals{
		Files: []model.FileFact{
			{Path: "/home/user/.openclaw/openclaw.json", Exists: true, Mode: "0644"},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT004" && f.IsFail() {
			found = true
			if f.Confidence != model.ConfidenceHigh {
				t.Errorf("AGT004: want ConfidenceHigh, got %v", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("AGT004: want failing finding for mode 0644")
	}
}

func TestAGT004_CorrectMode_Pass(t *testing.T) {
	c := findCheck(t, "AGT004")
	sigs := &model.Signals{
		Files: []model.FileFact{
			{Path: "/home/user/.openclaw/openclaw.json", Exists: true, Mode: "0600"},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT004" && f.IsFail() {
			t.Errorf("AGT004: should pass for mode 0600, got %+v", f)
		}
	}
}

func TestAGT004_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT004")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT004: want NotAssessed, got %+v", findings)
	}
}

// TestRFX8_AGT004_OwnerOnlyMode is the parser-fed regression test for RFX-8/AGT004.
// Owner-only modes (0700, 0600) MUST NOT flag; group/other bits (0644, 0660) MUST flag.
// The previous code used n > 0o600 which incorrectly flagged 0700 (owner-execute bit).
func TestRFX8_AGT004_OwnerOnlyMode(t *testing.T) {
	c := findCheck(t, "AGT004")
	tests := []struct {
		name     string
		mode     string
		wantFail bool
	}{
		{
			name:     "RFX-8 mode 0700 (owner-only rwx) must NOT flag",
			mode:     "0700",
			wantFail: false,
		},
		{
			name:     "RFX-8 mode 0600 (owner-only rw) must NOT flag",
			mode:     "0600",
			wantFail: false,
		},
		{
			name:     "RFX-8 mode 0644 (group/other read) must flag",
			mode:     "0644",
			wantFail: true,
		},
		{
			name:     "RFX-8 mode 0660 (group read+write) must flag",
			mode:     "0660",
			wantFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs := &model.Signals{
				Files: []model.FileFact{
					{Path: "/home/user/.openclaw/openclaw.json", Exists: true, Mode: tt.mode},
				},
			}
			findings := c.Run(makeCtxWithCollector(sigs))
			hasFail := false
			for _, f := range findings {
				if f.CheckID == "AGT004" && f.IsFail() {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Errorf("mode %s: wantFail=%v got hasFail=%v findings=%+v", tt.mode, tt.wantFail, hasFail, findings)
			}
		})
	}
}
