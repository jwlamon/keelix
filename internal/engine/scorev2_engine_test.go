package engine_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/model"

	_ "github.com/jakelamon/keelix/internal/checks/all"
)

// The engine must report the v2 scoring model and a rating that is one of the
// three traffic-light grades, with sub-scores present.
func TestScanUsesV2ScoringModel(t *testing.T) {
	in := engine.Input{
		ComposePath:  filepath.Join("..", "..", "testdata", "vulnerable", "docker-compose.yml"),
		FirewallPath: filepath.Join("..", "..", "testdata", "vulnerable", "ufw.txt"),
		Options:      model.ScanOptions{NoProbe: true},
	}
	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.ScoringModel != "v2" {
		t.Fatalf("ScoringModel = %q, want v2", r.ScoringModel)
	}
	switch r.Rating {
	case "RED", "YELLOW", "GREEN":
	default:
		t.Fatalf("Rating = %q, want RED/YELLOW/GREEN", r.Rating)
	}
	if len(r.SubScores) == 0 {
		t.Fatal("expected per-group SubScores on the vulnerable stack")
	}
	// v1 Counts must still be populated.
	if r.Counts.Critical == 0 {
		t.Fatal("expected critical counts on the vulnerable stack")
	}
}
