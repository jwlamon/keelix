package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/model"

	_ "github.com/jakelamon/keelix/internal/checks/all"
)

func TestScanSignalsPathPopulatesCollectorAndNotAssessed(t *testing.T) {
	// Inject one not-assessed finding; restore the hook afterward.
	prev := extraFindings
	extraFindings = func(*model.ScanContext) []model.Finding {
		return []model.Finding{{
			CheckID:  "ZZZ999",
			Group:    model.GroupHardening,
			Title:    "AppArmor profile not assessed",
			Severity: model.SeverityWarning,
			Detail:   "host-level check could not run",
			Status:   model.StatusNotAssessed,
		}}
	}
	defer func() { extraFindings = prev }()

	in := Input{
		ComposePath: filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: filepath.Join("testdata", "signals.json"),
		},
	}
	r, err := Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Collector populated from the fixture.
	if r.Collector == nil {
		t.Fatal("expected Collector populated from SignalsPath fixture")
	}
	if got := r.Collector.Platform.OS; got != "linux" {
		t.Errorf("Collector.Platform.OS = %q, want linux", got)
	}
	if _, ok := r.Collector.SocketByPort(5432); !ok {
		t.Error("expected fixture socket on port 5432")
	}

	// The not-assessed finding is surfaced in NotAssessed...
	foundNA := false
	for _, f := range r.NotAssessed {
		if f.CheckID == "ZZZ999" {
			foundNA = true
		}
	}
	if !foundNA {
		t.Error("expected ZZZ999 in Result.NotAssessed")
	}
	// ...and excluded from the score: a clean stack with one *excluded*
	// not-assessed warning must still grade GREEN.
	if r.Rating != "GREEN" {
		t.Errorf("Rating = %q; not-assessed finding must not lower the score (want GREEN)", r.Rating)
	}
}
