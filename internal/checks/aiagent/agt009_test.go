package aiagent_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestAGT009_TelegramDmOpen(t *testing.T) {
	c := findCheck(t, "AGT009")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values:      map[string]string{"channels.telegram.dmPolicy": "open"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT009" && f.IsFail() {
			found = true
			if f.Confidence != model.ConfidenceHigh {
				t.Errorf("AGT009: want ConfidenceHigh, got %v", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("AGT009: want failing finding for telegram.dmPolicy=open")
	}
}

func TestAGT009_DiscordGroupOpen(t *testing.T) {
	c := findCheck(t, "AGT009")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values:      map[string]string{"channels.discord.groupPolicy": "open"},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT009" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT009: want failing finding for discord.groupPolicy=open")
	}
}

func TestAGT009_RestrictedPolicies_Pass(t *testing.T) {
	c := findCheck(t, "AGT009")
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					"channels.discord.groupPolicy": "allowlist",
					"channels.telegram.dmPolicy":   "allowlist",
				},
			},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT009" && f.IsFail() {
			t.Errorf("AGT009: restricted policies should pass, got %+v", f)
		}
	}
}

func TestAGT009_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT009")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT009: want NotAssessed, got %+v", findings)
	}
}
