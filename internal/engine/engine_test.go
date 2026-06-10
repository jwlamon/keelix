package engine_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/model"

	// Register the full check library.
	_ "github.com/jakelamon/keelix/internal/checks/all"
)

// TestEveryCatalogEntryHasARegisteredCheck guards against a check package
// forgetting to register one of its checks (or a check referencing an ID the
// catalog does not define). The registered set and the catalog must match
// exactly — no exemptions.
func TestEveryCatalogEntryHasARegisteredCheck(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range model.Registered() {
		registered[c.ID()] = true
		if !catalog.Has(c.ID()) {
			t.Errorf("registered check %q has no catalog entry", c.ID())
		}
	}
	for _, e := range catalog.All() {
		if !registered[e.ID] {
			t.Errorf("catalog entry %q has no registered check", e.ID)
		}
	}
	if len(registered) != len(catalog.All()) {
		t.Errorf("registered %d checks but catalog has %d entries (parity required)",
			len(registered), len(catalog.All()))
	}
}

func hasFinding(r *model.Result, checkID string, sev model.Severity) bool {
	for _, f := range r.Findings {
		if f.CheckID == checkID && f.Severity == sev {
			return true
		}
	}
	return false
}

func TestScanVulnerableStack(t *testing.T) {
	in := engine.Input{
		ComposePath:  filepath.Join("..", "..", "testdata", "vulnerable", "docker-compose.yml"),
		FirewallPath: filepath.Join("..", "..", "testdata", "vulnerable", "ufw.txt"),
		Options:      model.ScanOptions{NoProbe: true},
	}
	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Counts.Critical == 0 {
		t.Fatal("expected critical findings on the vulnerable stack")
	}
	if r.Rating == "GREEN" {
		t.Errorf("vulnerable stack rating = %q; expected RED or YELLOW (not GREEN)", r.Rating)
	}
	// Spot-check the marquee findings.
	want := []struct {
		id  string
		sev model.Severity
	}{
		{"FW001", model.SeverityCritical},   // Docker bypasses UFW for 5432/6379
		{"HRD001", model.SeverityCritical},  // privileged
		{"HRD003", model.SeverityCritical},  // docker.sock
		{"PRX003", model.SeverityCritical},  // traefik api.insecure
		{"SEC003", model.SeverityCritical},  // weak password
		{"AUTH002", model.SeverityCritical}, // grafana default creds
	}
	for _, w := range want {
		if !hasFinding(r, w.id, w.sev) {
			t.Errorf("expected %s at severity %v on vulnerable stack", w.id, w.sev)
		}
	}
	// Every failing finding must carry at least one control mapping (evidence).
	for _, f := range r.Findings {
		if f.IsFail() && len(f.Controls) == 0 {
			t.Errorf("finding %s has no control mappings", f.CheckID)
		}
	}
}

func TestScanCleanStack(t *testing.T) {
	in := engine.Input{
		ComposePath: filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml"),
		Options:     model.ScanOptions{NoProbe: true},
	}
	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Counts.Critical != 0 {
		t.Errorf("clean stack has %d critical findings; want 0", r.Counts.Critical)
		for _, f := range r.Fails() {
			t.Logf("  unexpected: %s %s (%s)", f.CheckID, f.Title, f.Severity)
		}
	}
	if r.Score < 85 {
		t.Errorf("clean stack scored %d; want GREEN (>=85)", r.Score)
	}
}
