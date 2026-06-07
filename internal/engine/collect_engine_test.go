package engine_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jwlamon/keelix/internal/engine"
	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// With collection disabled the engine must leave ScanContext.Collector nil and
// still produce a scored Result.
func TestScanCollectDisabledHasNilCollector(t *testing.T) {
	in := engine.Input{
		ComposePath: filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml"),
		Options:     model.ScanOptions{NoProbe: true, Collect: false},
	}
	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Collector != nil {
		t.Fatalf("expected nil Collector when Collect=false, got %+v", r.Collector)
	}
	if r.Score < 0 || r.Score > 100 {
		t.Fatalf("score out of range: %d", r.Score)
	}
}
