package catalog

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestAllEntriesWellFormed(t *testing.T) {
	for _, e := range All() {
		if e.ID == "" {
			t.Errorf("entry with empty ID: %+v", e)
		}
		if e.Title == "" {
			t.Errorf("%s: empty title", e.ID)
		}
		if e.Rationale == "" {
			t.Errorf("%s: empty rationale", e.ID)
		}
		if e.Group == "" {
			t.Errorf("%s: empty group", e.ID)
		}
		if len(e.Controls) == 0 {
			t.Errorf("%s: no control mappings", e.ID)
		}
		for _, c := range e.Controls {
			if c.Framework == "" || c.ID == "" || c.Title == "" {
				t.Errorf("%s: malformed control %+v", e.ID, c)
			}
		}
	}
}

func TestEveryGroupHasACheck(t *testing.T) {
	// pendingGroups must be empty: all groups have catalog entries.
	// If a group is added to model.GroupOrder without catalog entries, add it
	// here temporarily and remove it only after entries land.
	pendingGroups := map[model.CheckGroup]bool{}
	if len(pendingGroups) != 0 {
		t.Errorf("pendingGroups must be empty when all groups have catalog entries; found %d", len(pendingGroups))
	}
	seen := map[model.CheckGroup]bool{}
	for _, e := range All() {
		seen[e.Group] = true
	}
	for _, g := range model.GroupOrder {
		if pendingGroups[g] {
			continue
		}
		if !seen[g] {
			t.Errorf("group %q has no checks in the catalog", g)
		}
	}
}

func TestFindingPrefillsFromEntry(t *testing.T) {
	f := Get("EXP001").Finding()
	if f.CheckID != "EXP001" {
		t.Fatalf("CheckID = %q", f.CheckID)
	}
	if f.Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", f.Severity)
	}
	if len(f.Controls) == 0 || f.Detail == "" {
		t.Fatalf("finding not prefilled: %+v", f)
	}
	// Mutating the finding's controls must not affect the catalog entry.
	f.Controls[0].ID = "MUTATED"
	if Get("EXP001").Controls[0].ID == "MUTATED" {
		t.Fatal("Finding() must deep-copy controls")
	}
}

func TestPassFinding(t *testing.T) {
	f := Get("HRD001").Pass("no privileged containers")
	if !f.Passed || f.Severity != model.SeverityOK {
		t.Fatalf("pass finding wrong: %+v", f)
	}
}

func TestGetUnknownPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on unknown ID")
		}
	}()
	Get("NOPE999")
}
