package all_test

import (
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// TestHostChecksRegistered asserts that at least one HST-prefixed check is
// present in the registry after importing internal/checks/all. This file must
// be written before internal/checks/host exists so the test fails to compile,
// confirming the blank-import is the load-bearing wiring.
func TestHostChecksRegistered(t *testing.T) {
	found := false
	for _, c := range model.Registered() {
		if len(c.ID()) >= 3 && c.ID()[:3] == "HST" {
			found = true
			break
		}
	}
	if !found {
		t.Error("no HST-prefixed check found in registry; internal/checks/host must be blank-imported in internal/checks/all")
	}
}

func TestSVCChecksRegistered(t *testing.T) {
	want := []string{"SVC001", "SVC002", "SVC003", "SVC004", "SVC050", "SVC051"}
	registered := map[string]bool{}
	for _, c := range model.Registered() {
		registered[c.ID()] = true
	}
	for _, id := range want {
		if !registered[id] {
			t.Errorf("%s: not registered in model.Registered()", id)
		}
	}
}

func TestSVCCatalogParity(t *testing.T) {
	// Every SVC-prefixed catalog entry must have a registered check.
	// Iterate catalog.All() so that adding or renaming a catalog entry is
	// automatically reflected here — a hardcoded slice would let a rename
	// silently pass this guard.
	registered := map[string]bool{}
	for _, c := range model.Registered() {
		registered[c.ID()] = true
	}
	for _, e := range catalog.All() {
		if !strings.HasPrefix(e.ID, "SVC") {
			continue
		}
		if !registered[e.ID] {
			t.Errorf("catalog entry %s has no registered check; add it to internal/checks/service/", e.ID)
		}
	}
}

func TestSUPChecksRegistered(t *testing.T) {
	want := []string{"SUP001", "SUP002", "SUP003", "SUP004"}
	registered := map[string]bool{}
	for _, c := range model.Registered() {
		registered[c.ID()] = true
	}
	for _, id := range want {
		if !registered[id] {
			t.Errorf("%s: not registered in model.Registered()", id)
		}
	}
}

func TestSUPCatalogParity(t *testing.T) {
	registered := map[string]bool{}
	for _, c := range model.Registered() {
		registered[c.ID()] = true
	}
	for _, e := range catalog.All() {
		if !strings.HasPrefix(e.ID, "SUP") {
			continue
		}
		if !registered[e.ID] {
			t.Errorf("catalog entry %s has no registered check; add it to internal/checks/supplychain/", e.ID)
		}
	}
}
