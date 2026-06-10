package score

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func mk(sev model.Severity) model.Finding {
	f := model.Finding{Severity: sev}
	if sev == model.SeverityOK {
		f.Passed = true
	}
	return f
}

func TestComputeCleanStackIsPerfect(t *testing.T) {
	findings := []model.Finding{mk(model.SeverityOK), mk(model.SeverityOK)}
	s, c := Compute(findings)
	if s != 100 {
		t.Fatalf("clean stack score = %d, want 100", s)
	}
	if c.Passed != 2 {
		t.Fatalf("passed = %d, want 2", c.Passed)
	}
}

func TestComputePenalizesBySeverity(t *testing.T) {
	findings := []model.Finding{
		mk(model.SeverityCritical), mk(model.SeverityCritical),
		mk(model.SeverityCritical), mk(model.SeverityCritical),
		mk(model.SeverityWarning), mk(model.SeverityWarning),
		mk(model.SeverityWarning), mk(model.SeverityWarning),
		mk(model.SeverityWarning), mk(model.SeverityWarning),
	}
	for i := 0; i < 12; i++ {
		findings = append(findings, mk(model.SeverityOK))
	}
	s, c := Compute(findings)
	// 4*10 + 6*3 = 58 penalty => 42.
	if s != 42 {
		t.Fatalf("score = %d, want 42", s)
	}
	if c.Critical != 4 || c.Warning != 6 || c.Passed != 12 {
		t.Fatalf("counts = %+v", c)
	}
	if Rating(s) != "RED" {
		t.Fatalf("rating = %s, want RED", Rating(s))
	}
}

func TestScoreFloorsAtZero(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, mk(model.SeverityCritical))
	}
	s, _ := Compute(findings)
	if s != 0 {
		t.Fatalf("score = %d, want 0 (floored)", s)
	}
}

func TestRatingThresholds(t *testing.T) {
	cases := map[int]string{100: "GREEN", 85: "GREEN", 84: "YELLOW", 50: "YELLOW", 49: "RED", 0: "RED"}
	for in, want := range cases {
		if got := Rating(in); got != want {
			t.Errorf("Rating(%d) = %s, want %s", in, got, want)
		}
	}
}

func TestCountExcludesNotAssessed(t *testing.T) {
	// A NotAssessed finding with Critical severity must NOT appear in Counts.Critical.
	f := model.Finding{
		Severity: model.SeverityCritical,
		Status:   model.StatusNotAssessed,
	}
	c := Count([]model.Finding{f})
	if c.Critical != 0 {
		t.Fatalf("Count.Critical = %d, want 0 for a NotAssessed finding", c.Critical)
	}
}
