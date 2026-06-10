package aiagent_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestAGT007_CronEnabledPlusAutoApproval(t *testing.T) {
	c := findCheck(t, "AGT007")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-cron",
				SchemaKnown: true,
				Values: map[string]string{
					"anyEnabled":       "true",
					"jobsEnabledCount": "2",
				},
			},
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
		if f.CheckID == "AGT007" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT007: want failing finding for cron+auto-approval combo")
	}
}

func TestAGT007_CronEnabledButNoAutoApproval_Pass(t *testing.T) {
	c := findCheck(t, "AGT007")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-cron",
				SchemaKnown: true,
				Values: map[string]string{
					"anyEnabled":       "true",
					"jobsEnabledCount": "2",
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
		if f.CheckID == "AGT007" && f.IsFail() {
			t.Errorf("AGT007: cron+on-miss should NOT fire, got %+v", f)
		}
	}
}

func TestAGT007_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT007")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT007: want NotAssessed, got %+v", findings)
	}
}
