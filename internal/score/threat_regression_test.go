package score

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// nonCVEFindings is a representative mixed set with NO Metadata["cve"]. Its
// numeric score, rating, and per-finding risk must be byte-identical before and
// after the SP4 threat() change (which only affects findings carrying a CVE).
func nonCVEFindings() []model.Finding {
	return []model.Finding{
		{ // failing critical, internet, high → risk = 9*1.0*1.0*1.0 = 9
			CheckID: "EXP001", Group: model.GroupExposure,
			Severity: model.SeverityCritical, Status: model.StatusAssessed,
			BaseImpact: 9.0, ExposureClass: model.ExposureInternet, Confidence: model.ConfidenceHigh,
			Fatal: true,
		},
		{ // failing warning, LAN, medium → risk = 5*0.35*1.0*0.6 = 1.05
			CheckID: "FW002", Group: model.GroupFirewall,
			Severity: model.SeverityWarning, Status: model.StatusAssessed,
			BaseImpact: 5.0, ExposureClass: model.ExposureLAN, Confidence: model.ConfidenceMedium,
		},
		{ // passing assessed → denominator only
			CheckID: "HRD004", Group: model.GroupHardening,
			Severity: model.SeverityOK, Passed: true, Status: model.StatusAssessed,
			BaseImpact: 5.0,
		},
		{ // info, localhost, high → counted under info cap
			CheckID: "HRD005", Group: model.GroupHardening,
			Severity: model.SeverityInfo, Status: model.StatusAssessed,
			BaseImpact: 2.0, ExposureClass: model.ExposureLocalhost, Confidence: model.ConfidenceHigh,
		},
	}
}

func TestNonCVEScoreUnchanged(t *testing.T) {
	fs := nonCVEFindings()
	// These exact values are the SP0–SP3 behavior and MUST NOT move in SP4.
	numeric, rating, _, _ := ComputeV2(fs)
	const wantNumeric = 51 // round(100*(1 - (9+1.05+0.20)/21)) = round(51.19); plan comment had info risk as 0.04 (wrong), actual=2*0.10*1.0=0.20
	if numeric != wantNumeric {
		t.Errorf("numeric = %d, want %d (non-CVE score must be unchanged by SP4)", numeric, wantNumeric)
	}
	if rating != "RED" {
		t.Errorf("rating = %q, want RED (EXP001 fatal internet high caps RED)", rating)
	}
	// Per-finding risk for the non-CVE critical must equal the un-weighted value.
	if got := risk(fs[0]); got != 9.0 {
		t.Errorf("risk(non-CVE EXP001) = %v, want 9.0", got)
	}
}
