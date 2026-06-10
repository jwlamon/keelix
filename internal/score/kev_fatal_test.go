package score

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// kevFinding is a high-confidence critical SUP-style finding carrying a KEV CVE.
func kevFinding(exp model.ExposureClass) model.Finding {
	return model.Finding{
		CheckID:       "SUP003",
		Group:         model.GroupSupplyChain,
		Title:         "Image affected by a known-exploited CVE (CISA KEV)",
		Severity:      model.SeverityCritical,
		Status:        model.StatusAssessed,
		BaseImpact:    9.0,
		Confidence:    model.ConfidenceHigh,
		ExposureClass: exp,
		Metadata:      map[string]string{"cve": "CVE-2021-44228"},
		// Fatal intentionally false on input; applyKEVFatal must set it.
	}
}

func TestApplyKEVFatal_RoutableEscalates(t *testing.T) {
	for _, exp := range []model.ExposureClass{model.ExposureLAN, model.ExposureFiltered, model.ExposureInternet} {
		out := applyKEVFatal([]model.Finding{kevFinding(exp)})
		if !out[0].Fatal {
			t.Errorf("exposure %v: KEV finding should be escalated to Fatal", exp)
		}
	}
}

func TestApplyKEVFatal_LocalhostDoesNotEscalate(t *testing.T) {
	for _, exp := range []model.ExposureClass{model.ExposureLocalhost, model.ExposureOverlay, model.ExposureUnknown} {
		out := applyKEVFatal([]model.Finding{kevFinding(exp)})
		if out[0].Fatal {
			t.Errorf("exposure %v: KEV finding must NOT be escalated to Fatal", exp)
		}
	}
}

func TestApplyKEVFatal_DoesNotMutateInput(t *testing.T) {
	in := []model.Finding{kevFinding(model.ExposureInternet)}
	_ = applyKEVFatal(in)
	if in[0].Fatal {
		t.Error("applyKEVFatal mutated the caller's slice; it must copy")
	}
}

func TestComputeV2_KEVInternetCapsRED(t *testing.T) {
	// KEV CVE at internet exposure → applyKEVFatal sets Fatal → network RED cap.
	// Pad with passes so the numeric band is GREEN; the cap is what drives RED.
	findings := []model.Finding{kevFinding(model.ExposureInternet)}
	for i := 0; i < 20; i++ {
		findings = append(findings, model.Finding{
			Severity: model.SeverityOK, Passed: true,
			Status: model.StatusAssessed, BaseImpact: 10.0,
		})
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Errorf("rating = %q, want RED (KEV + internet)", rating)
	}
	if cap == nil || cap.Grade != "RED" {
		t.Errorf("expected a RED cap driver, got %+v", cap)
	}
	if cap != nil && cap.CheckID != "SUP003" {
		t.Errorf("cap driver = %q, want SUP003", cap.CheckID)
	}
}

func TestComputeV2_KEVLocalhostDoesNotCap(t *testing.T) {
	// KEV CVE at localhost → no Fatal escalation → no RED cap from this finding.
	_, _, _, cap := ComputeV2([]model.Finding{kevFinding(model.ExposureLocalhost)})
	if cap != nil {
		t.Errorf("KEV at localhost should not drive a cap, got %+v", cap)
	}
}

func TestComputeV2_NonKEVCVEAtInternetDoesNotCap(t *testing.T) {
	// High-EPSS NON-KEV CVE at internet must NOT auto-escalate to Fatal.
	f := kevFinding(model.ExposureInternet)
	f.Metadata["cve"] = "CVE-1999-0001" // real EPSS-present (~0.77 pctl), NOT KEV
	f.Fatal = false
	_, _, _, cap := ComputeV2([]model.Finding{f})
	if cap != nil {
		t.Errorf("non-KEV EPSS CVE must not auto-cap RED, got %+v", cap)
	}
}

// SF-3: applyKEVFatal must only escalate Critical-severity findings.
// A Warning-severity KEV finding at a routable exposure must NOT be escalated.
func TestApplyKEVFatal_OnlyEscalatesCritical(t *testing.T) {
	warnFinding := model.Finding{
		CheckID:       "SUP003",
		Severity:      model.SeverityWarning, // not Critical
		Status:        model.StatusAssessed,
		BaseImpact:    5.0,
		Confidence:    model.ConfidenceHigh,
		ExposureClass: model.ExposureInternet,
		Metadata:      map[string]string{"cve": "CVE-2021-44228"},
		Fatal:         false,
	}
	out := applyKEVFatal([]model.Finding{warnFinding})
	if out[0].Fatal {
		t.Error("Warning-severity KEV finding must NOT be escalated to Fatal by applyKEVFatal")
	}
}

// SF-3: SUP003 at localhost should never cap RED, even though it carries a KEV CVE.
// This test creates a finding exactly as the catalog would emit it (Fatal=false)
// and confirms that at ExposureLocalhost no RED cap fires.
func TestComputeV2_SUP003KEVLocalhostNoRedCap(t *testing.T) {
	// Simulate the catalog entry as it will be after SF-3: Fatal=false.
	f := model.Finding{
		CheckID:       "SUP003",
		Group:         model.GroupSupplyChain,
		Title:         "Image affected by a known-exploited CVE (CISA KEV)",
		Severity:      model.SeverityCritical,
		Status:        model.StatusAssessed,
		BaseImpact:    9.0,
		Confidence:    model.ConfidenceHigh,
		ExposureClass: model.ExposureLocalhost,
		Metadata:      map[string]string{"cve": "CVE-2021-44228"},
		Fatal:         false, // catalog must NOT pre-stamp Fatal; applyKEVFatal handles it
	}
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so a cap is what would lower it", n, band(n))
	}
	if rating == "RED" {
		t.Errorf("SUP003 KEV at localhost: rating = RED, want non-RED (localhost must not cap)")
	}
	if cap != nil && cap.Grade == "RED" {
		t.Errorf("SUP003 KEV at localhost: RED cap driver = %+v, want nil cap", cap)
	}
}

// SF-3: SUP003 at ExposureInternet with KEV CVE must cap RED via applyKEVFatal.
// The catalog entry has Fatal=false; applyKEVFatal escalates it conditionally.
func TestComputeV2_SUP003KEVInternetCapsRED(t *testing.T) {
	f := model.Finding{
		CheckID:       "SUP003",
		Group:         model.GroupSupplyChain,
		Title:         "Image affected by a known-exploited CVE (CISA KEV)",
		Severity:      model.SeverityCritical,
		Status:        model.StatusAssessed,
		BaseImpact:    9.0,
		Confidence:    model.ConfidenceHigh,
		ExposureClass: model.ExposureInternet,
		Metadata:      map[string]string{"cve": "CVE-2021-44228"},
		Fatal:         false, // catalog must NOT pre-stamp Fatal; applyKEVFatal handles it
	}
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap is what drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Errorf("SUP003 KEV at internet: rating = %q, want RED", rating)
	}
	if cap == nil || cap.Grade != "RED" {
		t.Errorf("SUP003 KEV at internet: expected RED cap driver, got %+v", cap)
	}
	if cap != nil && cap.CheckID != "SUP003" {
		t.Errorf("cap driver CheckID = %q, want SUP003", cap.CheckID)
	}
}
