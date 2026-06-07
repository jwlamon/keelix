package aiagent_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestAGT001_OpenClawAskOff(t *testing.T) {
	c := findCheck(t, "AGT001")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values:      map[string]string{"tools.exec.ask": "off"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT001" && f.IsFail() {
			found = true
			if f.Severity != model.SeverityCritical {
				t.Errorf("AGT001: want Critical, got %s", f.Severity)
			}
			if f.Confidence != model.ConfidenceMedium {
				t.Errorf("AGT001: want ConfidenceMedium, got %v", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("AGT001: want a failing finding for ask==off, got %+v", findings)
	}
}

func TestAGT001_OpenClawAskOnMiss_NotAutoApproval(t *testing.T) {
	// "on-miss" is NOT auto-approval — must NOT fire AGT001.
	c := findCheck(t, "AGT001")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-exec-approvals",
				SchemaKnown: true,
				Values: map[string]string{
					"defaults.ask":         "on-miss",
					"defaults.askFallback": "deny",
				},
			},
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values:      map[string]string{"tools.exec.ask": "on-miss"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT001" && f.IsFail() {
			t.Errorf("AGT001: on-miss should NOT trigger auto-approval finding; got %+v", f)
		}
	}
}

func TestAGT001_ClaudeBypassPermissions(t *testing.T) {
	c := findCheck(t, "AGT001")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "claude-code-settings",
				SchemaKnown: true,
				Values:      map[string]string{"defaultMode": "bypassPermissions"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT001" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT001: want failing finding for Claude bypassPermissions")
	}
}

func TestAGT001_ClaudeSkipDangerous(t *testing.T) {
	c := findCheck(t, "AGT001")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "claude-code-settings",
				SchemaKnown: true,
				Values:      map[string]string{"skipDangerousModePermissionPrompt": "true"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT001" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT001: want failing finding for skipDangerousModePermissionPrompt==true")
	}
}

func TestAGT001_CodexAutoApproval(t *testing.T) {
	c := findCheck(t, "AGT001")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "codex-config",
				SchemaKnown: true,
				Values:      map[string]string{"approval_policy": "auto"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT001" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT001: want failing finding for Codex approval_policy==auto")
	}
}

func TestAGT001_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT001")
	ctx := &model.ScanContext{} // no Collector
	findings := c.Run(ctx)
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT001: want single NotAssessed finding when Collector==nil, got %+v", findings)
	}
}
