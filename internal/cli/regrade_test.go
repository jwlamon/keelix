package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// writeScanJSON writes a Result as JSON to dir/name and returns its path.
func writeScanJSON(t *testing.T, dir, name string, r model.Result) string {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestCollectScanPathsExpandsDirAndGlob(t *testing.T) {
	dir := t.TempDir()
	writeScanJSON(t, dir, "a.json", model.Result{})
	writeScanJSON(t, dir, "b.json", model.Result{})
	// A non-JSON file must be ignored when a bare directory is given.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write txt: %v", err)
	}

	// Bare directory => all *.json inside it.
	paths, err := collectScanPaths([]string{dir})
	if err != nil {
		t.Fatalf("collectScanPaths(dir): %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("dir expansion = %d paths, want 2: %v", len(paths), paths)
	}

	// Explicit glob.
	paths, err = collectScanPaths([]string{filepath.Join(dir, "*.json")})
	if err != nil {
		t.Fatalf("collectScanPaths(glob): %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("glob expansion = %d paths, want 2: %v", len(paths), paths)
	}
}

func TestRunRegradePrintsSummary(t *testing.T) {
	dir := t.TempDir()
	// One Result that regrades GREEN->RED under v2 (fatal/high/internet critical).
	worse := model.Result{Findings: []model.Finding{
		{
			Severity:      model.SeverityCritical,
			BaseImpact:    10,
			Confidence:    model.ConfidenceHigh,
			ExposureClass: model.ExposureInternet,
			Fatal:         true,
			Status:        model.StatusAssessed,
		},
		{Severity: model.SeverityOK, Passed: true, BaseImpact: 5, Status: model.StatusAssessed},
		{Severity: model.SeverityOK, Passed: true, BaseImpact: 5, Status: model.StatusAssessed},
	}}
	writeScanJSON(t, dir, "scan.json", worse)

	var buf strings.Builder
	if err := runRegrade(&buf, []string{dir}); err != nil {
		t.Fatalf("runRegrade: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 box will re-grade GREEN->RED") {
		t.Fatalf("output missing headline:\n%s", out)
	}
}

func TestRegradeCommandUsage(t *testing.T) {
	cmd := newRegradeCmd()
	if !strings.HasPrefix(cmd.Use, "regrade") {
		t.Fatalf("cmd.Use = %q, want prefix %q", cmd.Use, "regrade")
	}
}
