package collect

// TestRFX2_HST013_ParserFed is the PARSER-FED regression test for RFX-2 / HST013.
//
// The bug: hst013.go read cf.Values["unattended-upgrade"] (hyphen) but
// parseAptPeriodic emits the key "unattended_upgrade" (underscore). The pass
// branch was unreachable, so HST013 always fired RED on every well-configured
// Linux host that had Unattended-Upgrade "1" in its apt periodic config.
//
// This test exercises the complete pipeline:
//
//	parseAptPeriodic (real parser) -> collectConfigInternal -> HST013.Run()
//
// A synthetic model.Signals test (pre-populating Values["unattended-upgrade"])
// would pass regardless of the key name used inside Run(), which is exactly what
// masked this bug. Only a parser-fed test can catch the mismatch.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/host"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX2_HST013_AptPeriodicEnabled_Passes(t *testing.T) {
	// findRegisteredCheck is defined in rfx2_mcp001_test.go (same package).
	c := findRegisteredCheck(t, "HST013")

	// Run the real parseAptPeriodic parser over the committed fixture.
	// testdata/apt_20auto_upgrades.txt sets:
	//   APT::Periodic::Update-Package-Lists "1";
	//   APT::Periodic::Unattended-Upgrade "1";
	fixturePath := filepath.Join("testdata", "apt_20auto_upgrades.txt")
	fact := collectConfigInternal(fixturePath, parseAptPeriodic)

	if !fact.SchemaKnown {
		t.Fatalf("collectConfigInternal: SchemaKnown=false — fixture parse failed\nValues: %v", fact.Values)
	}

	// Verify the parser emits the underscore key (documents the contract).
	if fact.Values["unattended_upgrade"] != "1" {
		t.Fatalf("parser emitted wrong key or value: want unattended_upgrade=1, got Values=%v", fact.Values)
	}

	// Feed the real ConfigFact into HST013.Run() — must PASS (no RED finding).
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	for _, f := range findings {
		if f.Passed {
			return // correct: at least one passing finding
		}
	}
	t.Fatalf("HST013 fired RED on a host with Unattended-Upgrade=1 — key mismatch regression\nfindings: %+v\nValues: %v", findings, fact.Values)
}
