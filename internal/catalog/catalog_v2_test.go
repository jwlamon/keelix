package catalog

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestCatalogVersionBumped(t *testing.T) {
	if CatalogVersion != "2.4.0" {
		t.Fatalf("CatalogVersion = %q, want %q", CatalogVersion, "2.4.0")
	}
}

func TestFindingCarriesBaseImpactAndFatal(t *testing.T) {
	e := Entry{
		ID:         "TST999",
		Group:      model.GroupExposure,
		Title:      "test",
		Severity:   model.SeverityCritical,
		Rationale:  "because",
		Controls:   []model.ControlRef{soc2("CC6.6", "x")},
		BaseImpact: 9.5,
		Fatal:      true,
	}
	f := e.Finding()
	if f.BaseImpact != 9.5 {
		t.Errorf("Finding().BaseImpact = %v, want 9.5", f.BaseImpact)
	}
	if !f.Fatal {
		t.Error("Finding().Fatal = false, want true")
	}
}

func TestPassCarriesBaseImpactNotFatal(t *testing.T) {
	e := Entry{ID: "TST998", Group: model.GroupExposure, Title: "t",
		Severity: model.SeverityCritical, Rationale: "r",
		Controls: []model.ControlRef{soc2("CC6.6", "x")}, BaseImpact: 9, Fatal: true}
	f := e.Pass("")
	if f.BaseImpact != e.BaseImpact {
		t.Errorf("Pass().BaseImpact = %v, want %v (entry BaseImpact)", f.BaseImpact, e.BaseImpact)
	}
	if f.Fatal {
		t.Errorf("Pass().Fatal = true, want false (pass must never carry Fatal)")
	}
	if !f.Passed {
		t.Errorf("Pass().Passed = false, want true")
	}
	if f.Severity != model.SeverityOK {
		t.Errorf("Pass().Severity = %v, want SeverityOK", f.Severity)
	}
}
