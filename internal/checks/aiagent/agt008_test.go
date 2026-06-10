package aiagent_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestAGT008_WorkspaceOnlyFalse(t *testing.T) {
	c := findCheck(t, "AGT008")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values:      map[string]string{"tools.fs.workspaceOnly": "false"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT008" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT008: want failing finding for fs.workspaceOnly=false")
	}
}

func TestAGT008_BroadGlob(t *testing.T) {
	c := findCheck(t, "AGT008")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "claude-code-settings",
				SchemaKnown: true,
				Values: map[string]string{
					"permissions.allow.0": "**",
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT008" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT008: want failing finding for permissions.allow.0=**")
	}
}

func TestAGT008_WorkspaceOnlyTrue_Pass(t *testing.T) {
	c := findCheck(t, "AGT008")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values:      map[string]string{"tools.fs.workspaceOnly": "true"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT008" && f.IsFail() {
			t.Errorf("AGT008: workspaceOnly=true should pass, got %+v", f)
		}
	}
}

func TestAGT008_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT008")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT008: want NotAssessed, got %+v", findings)
	}
}
