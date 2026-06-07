package regrade

import (
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

// fail builds a failing finding with the given severity plus the v2 inputs
// (BaseImpact / Confidence / ExposureClass / Fatal) the v2 engine reads.
func fail(sev model.Severity, base float64, conf model.Confidence, exp model.ExposureClass, fatal bool) model.Finding {
	return model.Finding{
		Severity:      sev,
		BaseImpact:    base,
		Confidence:    conf,
		ExposureClass: exp,
		Fatal:         fatal,
		Status:        model.StatusAssessed,
	}
}

// pass builds a passing/assessed finding (raises the v2 denominator, zero risk).
func pass(base float64) model.Finding {
	return model.Finding{
		Severity:   model.SeverityOK,
		Passed:     true,
		BaseImpact: base,
		Status:     model.StatusAssessed,
	}
}

func TestRegradeTalliesTransitions(t *testing.T) {
	// r1: v1 sees one critical (penalty 10 => 90 => GREEN). v2 sees a fatal,
	// high-confidence, internet-exposed critical => RED cap. GREEN->RED.
	r1 := model.Result{Findings: []model.Finding{
		fail(model.SeverityCritical, 10, model.ConfidenceHigh, model.ExposureInternet, true),
		pass(5), pass(5), pass(5),
	}}
	// r2: a clean stack. v1 => 100 GREEN. v2 => 100 GREEN (no failing). GREEN->GREEN.
	r2 := model.Result{Findings: []model.Finding{pass(5), pass(5)}}

	rep := Regrade([]model.Result{r1, r2})

	if rep.Total != 2 {
		t.Fatalf("Total = %d, want 2", rep.Total)
	}
	if got := rep.Transitions["GREEN->RED"]; got != 1 {
		t.Fatalf("Transitions[GREEN->RED] = %d, want 1", got)
	}
	if got := rep.Transitions["GREEN->GREEN"]; got != 1 {
		t.Fatalf("Transitions[GREEN->GREEN] = %d, want 1", got)
	}
	if rep.Worsened != 1 {
		t.Fatalf("Worsened = %d, want 1", rep.Worsened)
	}
	if rep.Improved != 0 {
		t.Fatalf("Improved = %d, want 0", rep.Improved)
	}
}

func TestRegradeImprovedWhenV2Higher(t *testing.T) {
	// v1: six warnings (penalty 6*3=18 => 82 => YELLOW).
	// v2: same six warnings but localhost-bound, low confidence => tiny risk =>
	// stays GREEN. YELLOW->GREEN counts as Improved.
	var fs []model.Finding
	for i := 0; i < 6; i++ {
		fs = append(fs, fail(model.SeverityWarning, 4, model.ConfidenceLow, model.ExposureLocalhost, false))
	}
	for i := 0; i < 6; i++ {
		fs = append(fs, pass(4))
	}
	rep := Regrade([]model.Result{{Findings: fs}})

	if rep.Total != 1 {
		t.Fatalf("Total = %d, want 1", rep.Total)
	}
	if got := rep.Transitions["YELLOW->GREEN"]; got != 1 {
		t.Fatalf("Transitions[YELLOW->GREEN] = %d, want 1", got)
	}
	if rep.Improved != 1 {
		t.Fatalf("Improved = %d, want 1", rep.Improved)
	}
	if rep.Worsened != 0 {
		t.Fatalf("Worsened = %d, want 0", rep.Worsened)
	}
}

func TestRegradeEmptyInput(t *testing.T) {
	rep := Regrade(nil)
	if rep.Total != 0 {
		t.Fatalf("Total = %d, want 0", rep.Total)
	}
	if rep.Transitions == nil {
		t.Fatalf("Transitions is nil, want non-nil empty map")
	}
	if len(rep.Transitions) != 0 {
		t.Fatalf("Transitions = %v, want empty", rep.Transitions)
	}
}

func TestSummaryPluralizesBoxCorrectly(t *testing.T) {
	// n==1 should print "1 box will re-grade", not "1 boxes will re-grade".
	rep := RegradeReport{
		Total:       1,
		Transitions: map[string]int{"GREEN->RED": 1},
		Worsened:    1,
	}
	got := rep.Summary()
	if !strings.Contains(got, "1 box will re-grade GREEN->RED") {
		t.Fatalf("expected singular 'box'; got:\n%s", got)
	}
	if strings.Contains(got, "1 boxes") {
		t.Fatalf("unexpected plural '1 boxes'; got:\n%s", got)
	}

	// n==2 should print "2 boxes will re-grade".
	rep2 := RegradeReport{
		Total:       2,
		Transitions: map[string]int{"GREEN->RED": 2},
		Worsened:    2,
	}
	got2 := rep2.Summary()
	if !strings.Contains(got2, "2 boxes will re-grade GREEN->RED") {
		t.Fatalf("expected plural 'boxes'; got:\n%s", got2)
	}
}

func TestSummaryIsDeterministicAndCountsGreenToRed(t *testing.T) {
	rep := RegradeReport{
		Total: 4,
		Transitions: map[string]int{
			"GREEN->RED":    2,
			"GREEN->GREEN":  1,
			"YELLOW->GREEN": 1,
		},
		Worsened: 2,
		Improved: 1,
	}
	got := rep.Summary()

	// Headline must report the GREEN->RED count exactly.
	if !strings.Contains(got, "2 boxes will re-grade GREEN->RED") {
		t.Fatalf("summary missing GREEN->RED headline:\n%s", got)
	}
	// Table rows must be present and sorted (GREEN->GREEN before GREEN->RED
	// before YELLOW->GREEN, lexical).
	iGG := strings.Index(got, "GREEN->GREEN")
	iGR := strings.Index(got, "GREEN->RED")
	iYG := strings.Index(got, "YELLOW->GREEN")
	if iGG < 0 || iGR < 0 || iYG < 0 {
		t.Fatalf("summary missing a transition row:\n%s", got)
	}
	if !(iGG < iGR && iGR < iYG) {
		t.Fatalf("transition rows not sorted:\n%s", got)
	}
	// Totals line present.
	if !strings.Contains(got, "4 scans") {
		t.Fatalf("summary missing total count:\n%s", got)
	}
	// Determinism: same input => byte-identical output.
	if rep.Summary() != got {
		t.Fatalf("Summary not deterministic")
	}
}
