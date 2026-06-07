package score

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

// mkF builds a failing finding with the scoring-relevant fields set.
func mkF(impact float64, exp model.ExposureClass, conf model.Confidence) model.Finding {
	return model.Finding{
		Severity:      model.SeverityCritical,
		Status:        model.StatusAssessed,
		BaseImpact:    impact,
		ExposureClass: exp,
		Confidence:    conf,
	}
}

func TestThreatIsUnitInSP0(t *testing.T) {
	// threat() is a deliberate SP4 stub: always 1.0 until EPSS/KEV lands.
	if got := threat(model.Finding{}); got != 1.0 {
		t.Fatalf("threat() = %v, want 1.0", got)
	}
}

func TestRiskAndMaxRisk(t *testing.T) {
	// BaseImpact 8, Internet (×1.00), High confidence (×1.0), threat 1.0 => risk 8.
	f := mkF(8, model.ExposureInternet, model.ConfidenceHigh)
	if got := risk(f); got != 8 {
		t.Fatalf("risk(internet/high) = %v, want 8", got)
	}
	if got := maxrisk(f); got != 8 {
		t.Fatalf("maxrisk = %v, want 8 (BaseImpact)", got)
	}
	// Localhost (×0.10) + Low confidence (×0.3): 8 * 0.10 * 0.3 = 0.24.
	g := mkF(8, model.ExposureLocalhost, model.ConfidenceLow)
	if got := risk(g); got < 0.2399 || got > 0.2401 {
		t.Fatalf("risk(localhost/low) = %v, want ~0.24", got)
	}
	if got := maxrisk(g); got != 8 {
		t.Fatalf("maxrisk(localhost/low) = %v, want 8 (impact only)", got)
	}
}

// pass builds an assessed PASSING finding contributing only to the denominator.
func pass(impact float64) model.Finding {
	return model.Finding{
		Severity:   model.SeverityOK,
		Passed:     true,
		Status:     model.StatusAssessed,
		BaseImpact: impact,
	}
}

func TestComputeNumericCleanIsPerfect(t *testing.T) {
	// All passing & assessed => no risk in numerator, denom>0 => 100.
	findings := []model.Finding{pass(10), pass(8), pass(5)}
	n, _, _, _ := ComputeV2(findings)
	if n != 100 {
		t.Fatalf("clean assessed numeric = %d, want 100", n)
	}
}

func TestComputeNumericEmptyDenomIs100(t *testing.T) {
	// Nothing assessed at all (denom==0) => 100 by definition.
	na := mkF(9, model.ExposureInternet, model.ConfidenceHigh)
	na.Status = model.StatusNotAssessed
	n, _, _, _ := ComputeV2([]model.Finding{na})
	if n != 100 {
		t.Fatalf("all-not-assessed numeric = %d, want 100", n)
	}
}

func TestComputeNumericExcludesNotAssessed(t *testing.T) {
	// One assessed-failing internet critical (risk 9, maxrisk 9) plus a NOT
	// assessed finding that, if counted, would change the ratio. Expect the
	// not-assessed one to vanish from both sums.
	fail := mkF(9, model.ExposureInternet, model.ConfidenceHigh) // 1 - 9/9 = 0
	na := mkF(10, model.ExposureLocalhost, model.ConfidenceHigh)
	na.Status = model.StatusNotAssessed
	n, _, _, _ := ComputeV2([]model.Finding{fail, na})
	if n != 0 {
		t.Fatalf("numeric = %d, want 0 (not-assessed excluded from denom)", n)
	}
}

func TestComputeNumericNormalizesAcrossStackSize(t *testing.T) {
	// Same single internet critical; pad with passing assessed checks. The
	// ratio sum(risk)/sum(maxrisk) shrinks as the denominator grows, so the
	// two stacks are NOT required to be equal — but both must be well-defined
	// and the larger, mostly-passing stack must score strictly higher, proving
	// the score is a normalized ratio rather than an unbounded penalty sum.
	crit := mkF(8, model.ExposureInternet, model.ConfidenceHigh) // risk 8, maxrisk 8

	small := []model.Finding{crit, pass(8), pass(8)} // denom 24, risk 8 => 1-8/24=.667=>67
	big := []model.Finding{crit}
	for i := 0; i < 29; i++ {
		big = append(big, pass(8)) // denom 8+29*8=240, risk 8 => 1-8/240=.967=>97
	}
	ns, _, _, _ := ComputeV2(small)
	nb, _, _, _ := ComputeV2(big)
	if ns != 67 {
		t.Fatalf("small numeric = %d, want 67", ns)
	}
	if nb != 97 {
		t.Fatalf("big numeric = %d, want 97", nb)
	}
	if nb <= ns {
		t.Fatalf("big (%d) must exceed small (%d): score is a normalized ratio", nb, ns)
	}
}

// mkInfo builds a failing INFO finding with explicit weighting.
func mkInfo(impact float64, exp model.ExposureClass, conf model.Confidence) model.Finding {
	return model.Finding{
		Severity:      model.SeverityInfo,
		Status:        model.StatusAssessed,
		BaseImpact:    impact,
		ExposureClass: exp,
		Confidence:    conf,
	}
}

func TestComputeInfoRiskIsClamped(t *testing.T) {
	// 10 info findings, each risk = 4*1.00*1.0*1.0 = 4 => raw sumInfoRisk 40.
	// Clamped to infoCapPoints (5). Denominator = 10*maxrisk(4) = 40.
	// numeric = round(100*(1 - 5/40)) = round(87.5) = 88.
	var findings []model.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, mkInfo(4, model.ExposureInternet, model.ConfidenceHigh))
	}
	n, _, _, _ := ComputeV2(findings)
	if n != 88 {
		t.Fatalf("info-clamped numeric = %d, want 88 (info risk clamped to 5)", n)
	}
}

func TestComputeInfoClampDoesNotAffectNonInfo(t *testing.T) {
	// One internet critical (risk 8, maxrisk 8) + a pile of info (clamped to 5).
	// denom = 8 + 10*4 = 48; numerator risk = 8 + 5 = 13.
	// numeric = round(100*(1 - 13/48)) = round(72.916) = 73.
	findings := []model.Finding{mkF(8, model.ExposureInternet, model.ConfidenceHigh)}
	for i := 0; i < 10; i++ {
		findings = append(findings, mkInfo(4, model.ExposureInternet, model.ConfidenceHigh))
	}
	n, _, _, _ := ComputeV2(findings)
	if n != 73 {
		t.Fatalf("mixed numeric = %d, want 73", n)
	}
}

func TestBandThresholds(t *testing.T) {
	cases := map[int]string{
		100: "GREEN", 85: "GREEN", 84: "YELLOW",
		50: "YELLOW", 49: "RED", 0: "RED",
	}
	for in, want := range cases {
		if got := band(in); got != want {
			t.Errorf("band(%d) = %s, want %s", in, got, want)
		}
	}
}

// titled returns a finding with CheckID/Title set so we can assert the driver.
func titled(id, title string, f model.Finding) model.Finding {
	f.CheckID = id
	f.Title = title
	return f
}

func TestCapLocalhostCriticalDoesNotCap(t *testing.T) {
	// A localhost critical scores high (risk discounted to ~0.8) and must NOT
	// be capped below its band — localhost cannot CanCapRed and is not Internet.
	f := mkF(8, model.ExposureLocalhost, model.ConfidenceHigh)
	f.Fatal = true // even Fatal must not cap when exposure can't CanCapRed.
	pad := []model.Finding{f, pass(10), pass(10), pass(10)}
	n, rating, _, cap := ComputeV2(pad)
	if cap != nil {
		t.Fatalf("localhost critical produced a cap driver %+v, want nil", cap)
	}
	if rating != band(n) {
		t.Fatalf("rating %s != band(%d)=%s; localhost must not cap", rating, n, band(n))
	}
}

func TestCapInternetFatalHighCapsRed(t *testing.T) {
	// One assessed internet Fatal critical, padded with passes so the NUMERIC
	// band is GREEN — proving the cap (not the numeric) drives the RED grade.
	fatal := titled("EXP001", "Postgres open to the internet",
		mkF(2, model.ExposureInternet, model.ConfidenceHigh))
	fatal.Fatal = true
	findings := []model.Finding{fatal}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10)) // huge denom => numeric near 100/GREEN
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap is what lowers it", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED (Fatal+High+Internet caps RED)", rating)
	}
	if cap == nil {
		t.Fatal("cap driver = nil, want non-nil naming the finding")
	}
	if cap.CheckID != "EXP001" || cap.Title != "Postgres open to the internet" {
		t.Fatalf("cap driver = %+v, want EXP001/Postgres", cap)
	}
	if cap.Grade != "RED" {
		t.Fatalf("cap driver grade = %s, want RED", cap.Grade)
	}
}

func TestCapInternetFatalLowConfidenceDoesNotCap(t *testing.T) {
	// Fatal + Internet but LOW confidence => no RED cap (cap requires High).
	fatal := mkF(2, model.ExposureInternet, model.ConfidenceLow)
	fatal.Fatal = true
	findings := []model.Finding{fatal}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if cap != nil {
		t.Fatalf("low-confidence Fatal produced cap %+v, want nil", cap)
	}
	if rating != band(n) {
		t.Fatalf("rating %s != band(%d)=%s; low-confidence must not cap", rating, n, band(n))
	}
}

func TestCapYellowOnUnmitigatedInternetCritical(t *testing.T) {
	// High-confidence Internet Critical, NOT Fatal, NO mitigations => YELLOW cap.
	// Pad to a GREEN numeric so the cap is what lowers the grade.
	crit := titled("EXP009", "Redis open to the internet",
		mkF(2, model.ExposureInternet, model.ConfidenceHigh))
	findings := []model.Finding{crit}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN", n, band(n))
	}
	if rating != "YELLOW" {
		t.Fatalf("rating = %s, want YELLOW (unmitigated internet critical)", rating)
	}
	if cap == nil || cap.CheckID != "EXP009" || cap.Grade != "YELLOW" {
		t.Fatalf("cap driver = %+v, want EXP009/YELLOW", cap)
	}
}

func TestCapYellowSuppressedByMitigations(t *testing.T) {
	// Same internet critical but WITH a compensating control => no YELLOW cap.
	crit := mkF(2, model.ExposureInternet, model.ConfidenceHigh)
	crit.Mitigations = []string{"authenticating reverse proxy in front"}
	findings := []model.Finding{crit}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if cap != nil {
		t.Fatalf("mitigated critical produced cap %+v, want nil", cap)
	}
	if rating != band(n) {
		t.Fatalf("rating %s != band(%d)=%s; mitigation must suppress cap", rating, n, band(n))
	}
}

func TestCapInfoPileCannotForceRed(t *testing.T) {
	// A pile of internet-exposed info findings: risk clamps to 5, and info can
	// never trip the cap (cap looks at Critical/Fatal only). Grade stays at band.
	var findings []model.Finding
	for i := 0; i < 50; i++ {
		findings = append(findings, mkInfo(10, model.ExposureInternet, model.ConfidenceHigh))
	}
	n, rating, _, cap := ComputeV2(findings)
	if cap != nil {
		t.Fatalf("info pile produced cap %+v, want nil", cap)
	}
	if rating != band(n) {
		t.Fatalf("rating %s != band(%d)=%s; info must not cap", rating, n, band(n))
	}
	if rating == "RED" {
		t.Fatalf("info pile forced RED (n=%d); info risk must be clamped", n)
	}
}

// inGroup tags a finding with a CheckGroup.
func inGroup(g model.CheckGroup, f model.Finding) model.Finding {
	f.Group = g
	return f
}

func subFor(subs []model.GroupScore, g model.CheckGroup) (model.GroupScore, bool) {
	for _, s := range subs {
		if s.Group == g {
			return s, true
		}
	}
	return model.GroupScore{}, false
}

func TestSubScoresPerGroup(t *testing.T) {
	// Exposure group: one internet critical risk 8 / maxrisk 8 => 0.
	exp := inGroup(model.GroupExposure, mkF(8, model.ExposureInternet, model.ConfidenceHigh))
	// Hardening group: all passing => 100.
	h1 := inGroup(model.GroupHardening, pass(5))
	h2 := inGroup(model.GroupHardening, pass(5))
	// Hardening also has one NOT-assessed finding (excluded from ratio, counted).
	hna := inGroup(model.GroupHardening, mkF(9, model.ExposureInternet, model.ConfidenceHigh))
	hna.Status = model.StatusNotAssessed

	_, _, subs, _ := ComputeV2([]model.Finding{exp, h1, h2, hna})

	es, ok := subFor(subs, model.GroupExposure)
	if !ok {
		t.Fatal("no sub-score for GroupExposure")
	}
	if es.Score != 0 {
		t.Fatalf("exposure sub-score = %d, want 0", es.Score)
	}
	if es.NotAssessed != 0 {
		t.Fatalf("exposure NotAssessed = %d, want 0", es.NotAssessed)
	}

	hs, ok := subFor(subs, model.GroupHardening)
	if !ok {
		t.Fatal("no sub-score for GroupHardening")
	}
	if hs.Score != 100 {
		t.Fatalf("hardening sub-score = %d, want 100 (na excluded from ratio)", hs.Score)
	}
	if hs.NotAssessed != 1 {
		t.Fatalf("hardening NotAssessed = %d, want 1", hs.NotAssessed)
	}
}

func TestSubScoresFollowGroupOrder(t *testing.T) {
	// Two groups present, declared out of canonical order; result must follow
	// model.GroupOrder (Exposure before Hardening) and skip absent groups.
	h := inGroup(model.GroupHardening, pass(5))
	e := inGroup(model.GroupExposure, pass(5))
	_, _, subs, _ := ComputeV2([]model.Finding{h, e})
	if len(subs) != 2 {
		t.Fatalf("len(subs) = %d, want 2 (only present groups)", len(subs))
	}
	if subs[0].Group != model.GroupExposure || subs[1].Group != model.GroupHardening {
		t.Fatalf("sub order = [%s,%s], want [Exposure,Hardening]", subs[0].Group, subs[1].Group)
	}
}

// TestPassDenominatorInflatesScore verifies that passing findings with BaseImpact>0
// grow the denominator so a single fatal critical doesn't collapse everything to RED.
// One internet-exposed Fatal critical (BaseImpact 9, ConfidenceHigh) PLUS many
// passing checks each with BaseImpact>0 must score HIGH (>85) because the passes
// drive the normalized ratio toward 1. Adding more passes must also RAISE the
// numeric score (not stay flat), proving the denominator grows.
func TestPassDenominatorInflatesScore(t *testing.T) {
	// fatal critical: risk = 9 * 1.00 * 1.0 * 1.0 = 9, maxrisk = 9
	fatal := mkF(9, model.ExposureInternet, model.ConfidenceHigh)
	fatal.Fatal = true

	// 20 passing checks each with BaseImpact 9:
	// denom = 9 + 20*9 = 189, sumRisk = 9 => numeric = round(100*(1-9/189)) = round(95.24) = 95
	var findings20 []model.Finding
	findings20 = append(findings20, fatal)
	for i := 0; i < 20; i++ {
		findings20 = append(findings20, pass(9))
	}
	n20, _, _, _ := ComputeV2(findings20)
	if n20 <= 85 {
		t.Fatalf("with 20 passes numeric = %d, want >85 (passes inflate denominator)", n20)
	}

	// 40 passing checks each with BaseImpact 9:
	// denom = 9 + 40*9 = 369, sumRisk = 9 => numeric = round(100*(1-9/369)) = round(97.56) = 98
	var findings40 []model.Finding
	findings40 = append(findings40, fatal)
	for i := 0; i < 40; i++ {
		findings40 = append(findings40, pass(9))
	}
	n40, _, _, _ := ComputeV2(findings40)
	if n40 <= n20 {
		t.Fatalf("adding more passes must raise numeric: n20=%d n40=%d", n20, n40)
	}
}

// TestAllPassStackScores100 verifies that a finding set of only passing checks
// (sumRisk==0) yields numeric 100, regardless of how large the denominator is.
func TestAllPassStackScores100(t *testing.T) {
	findings := []model.Finding{pass(9), pass(7), pass(5), pass(3), pass(1)}
	n, _, _, _ := ComputeV2(findings)
	if n != 100 {
		t.Fatalf("all-pass stack numeric = %d, want 100 (sumRisk==0)", n)
	}
}

// mkFatal builds a Fatal assessed finding with the given severity, exposure and confidence.
func mkFatal(sev model.Severity, exp model.ExposureClass, conf model.Confidence) model.Finding {
	return model.Finding{
		Severity:      sev,
		Status:        model.StatusAssessed,
		BaseImpact:    8,
		ExposureClass: exp,
		Confidence:    conf,
		Fatal:         true,
	}
}

// TestCapNotAssessedFatalHighInternetNoCap asserts that a NotAssessed finding
// (even Fatal+High+Internet) never drives a cap.
func TestCapNotAssessedFatalHighInternetNoCap(t *testing.T) {
	f := mkFatal(model.SeverityCritical, model.ExposureInternet, model.ConfidenceHigh)
	f.Status = model.StatusNotAssessed
	findings := []model.Finding{f}
	for i := 0; i < 5; i++ {
		findings = append(findings, pass(10))
	}
	_, rating, _, cap := ComputeV2(findings)
	if cap != nil {
		t.Fatalf("NotAssessed fatal produced cap %+v, want nil", cap)
	}
	n, _, _, _ := ComputeV2(findings)
	if rating != band(n) {
		t.Fatalf("rating %s != band(%d)=%s; NotAssessed must not cap", rating, n, band(n))
	}
}

// TestCapFatalInfoHighInternetNoRedCap asserts that a Fatal+Info+High+Internet
// finding does NOT trigger a RED cap because Info is not a failing severity
// (IsFail()==false).
func TestCapFatalInfoHighInternetNoRedCap(t *testing.T) {
	f := mkFatal(model.SeverityInfo, model.ExposureInternet, model.ConfidenceHigh)
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if cap != nil && cap.Grade == "RED" {
		t.Fatalf("Fatal+Info produced RED cap %+v, want no RED cap (Info is not failing severity)", cap)
	}
	_ = n
	_ = rating
}

// TestCapFatalLANHighCapsRed asserts that Fatal+High+LAN does fire the RED cap
// (LAN satisfies CanCapRed).
func TestCapFatalLANHighCapsRed(t *testing.T) {
	f := titled("EXP010", "DB reachable on LAN",
		mkFatal(model.SeverityCritical, model.ExposureLAN, model.ConfidenceHigh))
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED (Fatal+High+LAN caps RED)", rating)
	}
	if cap == nil {
		t.Fatal("cap driver = nil, want non-nil")
	}
	if cap.Grade != "RED" {
		t.Fatalf("cap grade = %s, want RED", cap.Grade)
	}
}

// TestCapFatalFilteredHighCapsRed asserts that Fatal+High+Filtered does fire the
// RED cap (Filtered satisfies CanCapRed).
func TestCapFatalFilteredHighCapsRed(t *testing.T) {
	f := titled("EXP011", "DB behind firewall but Fatal",
		mkFatal(model.SeverityCritical, model.ExposureFiltered, model.ConfidenceHigh))
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED (Fatal+High+Filtered caps RED)", rating)
	}
	if cap == nil {
		t.Fatal("cap driver = nil, want non-nil")
	}
	if cap.Grade != "RED" {
		t.Fatalf("cap grade = %s, want RED", cap.Grade)
	}
}

// TestCapFatalOverlayHighNoCap asserts that Fatal+High+Overlay does NOT fire the
// RED cap because Overlay cannot CanCapRed.
func TestCapFatalOverlayHighNoCap(t *testing.T) {
	f := mkFatal(model.SeverityCritical, model.ExposureOverlay, model.ConfidenceHigh)
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	_, rating, _, cap := ComputeV2(findings)
	if cap != nil && cap.Grade == "RED" {
		t.Fatalf("Fatal+Overlay produced RED cap %+v, want no RED cap (Overlay cannot CanCapRed)", cap)
	}
	n, _, _, _ := ComputeV2(findings)
	_ = rating
	_ = n
}

// TestCapMediumConfidenceFatalInternetNoCap asserts that a medium-confidence
// Fatal+Internet finding does NOT drive a RED cap (cap requires ConfidenceHigh).
func TestCapMediumConfidenceFatalInternetNoCap(t *testing.T) {
	f := mkFatal(model.SeverityCritical, model.ExposureInternet, model.ConfidenceMedium)
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	_, _, _, cap := ComputeV2(findings)
	if cap != nil {
		t.Fatalf("Medium-confidence Fatal produced cap %+v, want nil (cap requires High)", cap)
	}
}

// TestCapDriverNilWhenBandAlreadyEqualsCapGrade asserts that CapDriver is nil
// when the numeric band equals the cap grade — no spurious cap driver reported.
func TestCapDriverNilWhenBandAlreadyEqualsCapGrade(t *testing.T) {
	// Fatal+High+Internet => RED cap. Use a single internet critical with no passes
	// so the numeric band is also RED. CapDriver must be nil because the cap didn't
	// lower the grade below the band — the band is already as bad as the cap.
	f := titled("EXP012", "Severe internet exposure",
		mkFatal(model.SeverityCritical, model.ExposureInternet, model.ConfidenceHigh))
	findings := []model.Finding{f}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "RED" {
		t.Fatalf("setup: band(%d)=%s, want RED so numeric band == cap grade", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED", rating)
	}
	if cap != nil {
		t.Fatalf("cap driver = %+v, want nil when numeric band already equals cap grade", cap)
	}
}

// mkAIFinding builds a finding in a given AI/MCP group with the supplied
// severity, confidence, exposure, and optional Fatal flag for autonomy-cap tests.
func mkAIFinding(group model.CheckGroup, sev model.Severity, conf model.Confidence,
	exp model.ExposureClass, fatal bool) model.Finding {
	return model.Finding{
		CheckID:       "AGT002",
		Title:         "AI agent lethal trifecta",
		Group:         group,
		Severity:      sev,
		Status:        model.StatusAssessed,
		BaseImpact:    9.5,
		ExposureClass: exp,
		Confidence:    conf,
		Fatal:         fatal,
	}
}

// TestCapAutonomyRedLocalhostFatalMedium asserts that a Fatal AI/MCP finding
// with ConfidenceMedium and ExposureLocalhost fires the autonomy RED cap even
// though Localhost cannot CanCapRed (the autonomy branch bypasses that gate).
func TestCapAutonomyRedLocalhostFatalMedium(t *testing.T) {
	f := mkAIFinding(model.GroupAIAgent, model.SeverityCritical,
		model.ConfidenceMedium, model.ExposureLocalhost, true)
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the autonomy cap is what lowers it", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED (Fatal AI/MCP ConfidenceMedium must fire autonomy RED cap)", rating)
	}
	if cap == nil {
		t.Fatal("cap driver = nil, want non-nil for autonomy RED cap")
	}
	if cap.Grade != "RED" {
		t.Fatalf("cap.Grade = %q, want %q", cap.Grade, "RED")
	}
	const wantReason = "dangerous AI agent / MCP capability"
	if cap.Reason != wantReason {
		t.Fatalf("cap.Reason = %q, want %q", cap.Reason, wantReason)
	}
	if cap.CheckID != "AGT002" {
		t.Fatalf("cap.CheckID = %q, want %q", cap.CheckID, "AGT002")
	}
}

// TestCapAutonomyRedMCPGroupFatalMedium asserts the autonomy cap also fires for
// GroupMCP (not only GroupAIAgent).
func TestCapAutonomyRedMCPGroupFatalMedium(t *testing.T) {
	f := mkAIFinding(model.GroupMCP, model.SeverityCritical,
		model.ConfidenceMedium, model.ExposureLocalhost, true)
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED (GroupMCP Fatal Medium must fire autonomy cap)", rating)
	}
	if cap == nil || cap.Reason != "dangerous AI agent / MCP capability" {
		t.Fatalf("cap = %+v, want autonomy reason", cap)
	}
}

// TestCapAutonomyLowConfidenceDoesNotCap asserts that ConfidenceLow Fatal AI
// findings do NOT fire the autonomy RED cap.
func TestCapAutonomyLowConfidenceDoesNotCap(t *testing.T) {
	f := mkAIFinding(model.GroupAIAgent, model.SeverityCritical,
		model.ConfidenceLow, model.ExposureLocalhost, true)
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	_, _, _, cap := ComputeV2(findings)
	if cap != nil && cap.Reason == "dangerous AI agent / MCP capability" {
		t.Fatalf("ConfidenceLow AI Fatal produced autonomy cap %+v; must not cap", cap)
	}
}

// TestCapBoxFatalHighInternetStillUsesNetworkReason asserts that a fatal BOX
// finding (GroupExposure) that satisfies the network RED cap uses the network
// reason, not the autonomy reason, even when AI findings are also present.
func TestCapBoxFatalHighInternetStillUsesNetworkReason(t *testing.T) {
	box := titled("EXP001", "Postgres open to the internet",
		mkFatal(model.SeverityCritical, model.ExposureInternet, model.ConfidenceHigh))
	box.Group = model.GroupExposure
	ai := mkAIFinding(model.GroupAIAgent, model.SeverityCritical,
		model.ConfidenceMedium, model.ExposureLocalhost, true)
	// Give the box finding a much higher risk so it wins the driver election.
	box.BaseImpact = 9.5
	findings := []model.Finding{box, ai}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("rating = %s, want RED", rating)
	}
	if cap == nil {
		t.Fatal("cap driver = nil")
	}
	const wantReason = "fatal exposure reachable from a routable network"
	if cap.Reason != wantReason {
		t.Fatalf("cap.Reason = %q, want %q (box finding must dominate)", cap.Reason, wantReason)
	}
}

// TestR2_2_SVC004_FatalCapsRed asserts that SVC004 (Elasticsearch X-Pack security
// disabled), which is SeverityCritical, can drive a RED cap when Fatal+Internet+High.
func TestR2_2_SVC004_FatalCapsRed(t *testing.T) {
	f := titled("SVC004", "Elasticsearch X-Pack security disabled",
		mkF(8.5, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("SVC004 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "SVC004" {
		t.Fatalf("cap driver = %+v, want SVC004", cap)
	}
}

// TestR2_2_SVC030_FatalCapsRed asserts that SVC030 (Vaultwarden open admin token)
// drives RED at ExposureInternet+ConfidenceHigh.
func TestR2_2_SVC030_FatalCapsRed(t *testing.T) {
	f := titled("SVC030", "Vaultwarden admin token absent or weak",
		mkF(8.5, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("SVC030 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "SVC030" {
		t.Fatalf("cap driver = %+v, want SVC030", cap)
	}
}

// TestR2_2_SVC032_FatalCapsRed asserts that SVC032 (Jenkins no-auth → RCE)
// drives RED at ExposureInternet+ConfidenceHigh.
func TestR2_2_SVC032_FatalCapsRed(t *testing.T) {
	f := titled("SVC032", "Jenkins security disabled",
		mkF(8.5, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("SVC032 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "SVC032" {
		t.Fatalf("cap driver = %+v, want SVC032", cap)
	}
}

// TestR2_2_SVC050_FatalCapsRed asserts that SVC050 (MinIO default creds)
// drives RED at ExposureInternet+ConfidenceHigh.
func TestR2_2_SVC050_FatalCapsRed(t *testing.T) {
	f := titled("SVC050", "MinIO running with default root credentials",
		mkF(8.5, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("SVC050 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "SVC050" {
		t.Fatalf("cap driver = %+v, want SVC050", cap)
	}
}

// TestR2_2_FW006_FatalCapsRed asserts that FW006 (kubelet anonymous auth)
// drives RED at ExposureInternet+ConfidenceHigh.
func TestR2_2_FW006_FatalCapsRed(t *testing.T) {
	f := titled("FW006", "k3s/kubelet anonymous authentication enabled",
		mkF(9.0, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("FW006 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "FW006" {
		t.Fatalf("cap driver = %+v, want FW006", cap)
	}
}

// TestCapAISubScoresAppearInGroupOrder asserts that GroupAIAgent and GroupMCP
// findings appear as sub-scores in the canonical GroupOrder position.
func TestCapAISubScoresAppearInGroupOrder(t *testing.T) {
	ai := mkAIFinding(model.GroupAIAgent, model.SeverityCritical,
		model.ConfidenceMedium, model.ExposureLocalhost, false)
	mcp := mkAIFinding(model.GroupMCP, model.SeverityWarning,
		model.ConfidenceHigh, model.ExposureLocalhost, false)
	exp := inGroup(model.GroupExposure, pass(8))

	_, _, subs, _ := ComputeV2([]model.Finding{ai, mcp, exp})

	_, hasAI := subFor(subs, model.GroupAIAgent)
	_, hasMCP := subFor(subs, model.GroupMCP)
	if !hasAI {
		t.Error("no sub-score for GroupAIAgent")
	}
	if !hasMCP {
		t.Error("no sub-score for GroupMCP")
	}

	// GroupAIAgent and GroupMCP must appear after GroupExposure in the subs slice.
	expIdx := -1
	aiIdx := -1
	mcpIdx := -1
	for i, s := range subs {
		switch s.Group {
		case model.GroupExposure:
			expIdx = i
		case model.GroupAIAgent:
			aiIdx = i
		case model.GroupMCP:
			mcpIdx = i
		}
	}
	if aiIdx <= expIdx {
		t.Errorf("GroupAIAgent sub (idx %d) must come after GroupExposure (idx %d)", aiIdx, expIdx)
	}
	if mcpIdx <= expIdx {
		t.Errorf("GroupMCP sub (idx %d) must come after GroupExposure (idx %d)", mcpIdx, expIdx)
	}
}

// TestR4_3_SVC010_FatalCapsRed asserts that SVC010 (*arr application no-auth)
// drives RED at ExposureInternet+ConfidenceHigh after R4-3 makes it Fatal.
func TestR4_3_SVC010_FatalCapsRed(t *testing.T) {
	f := titled("SVC010", "*arr application authentication disabled",
		mkF(8.0, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("SVC010 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "SVC010" {
		t.Fatalf("cap driver = %+v, want SVC010", cap)
	}
}

// TestR4_3_SVC060_FatalCapsRed asserts that SVC060 (Traefik api.insecure=true)
// drives RED at ExposureInternet+ConfidenceHigh after R4-3 makes it Fatal.
func TestR4_3_SVC060_FatalCapsRed(t *testing.T) {
	f := titled("SVC060", "Traefik API/dashboard exposed insecurely (api.insecure=true)",
		mkF(8.0, model.ExposureInternet, model.ConfidenceHigh))
	f.Fatal = true
	findings := []model.Finding{f}
	for i := 0; i < 20; i++ {
		findings = append(findings, pass(10))
	}
	n, rating, _, cap := ComputeV2(findings)
	if band(n) != "GREEN" {
		t.Fatalf("setup: band(%d)=%s, want GREEN so the cap drives RED", n, band(n))
	}
	if rating != "RED" {
		t.Fatalf("SVC060 rating = %s, want RED (Fatal+Internet+High must cap RED)", rating)
	}
	if cap == nil || cap.CheckID != "SVC060" {
		t.Fatalf("cap driver = %+v, want SVC060", cap)
	}
}

// TestRisk_AIMCPFullWeightNoLocalDiscount locks the calibration decision: AI/MCP
// findings weigh at full BaseImpact regardless of (localhost) exposure, while
// box-domain findings keep the exposure discount.
func TestRisk_AIMCPFullWeightNoLocalDiscount(t *testing.T) {
	ai := model.Finding{Group: model.GroupAIAgent, BaseImpact: 9.0, ExposureClass: model.ExposureLocalhost, Confidence: model.ConfidenceHigh}
	if got := risk(ai); got != 9.0 {
		t.Errorf("AI/agent finding risk = %v, want 9.0 (full weight, no local discount)", got)
	}
	mcp := model.Finding{Group: model.GroupMCP, BaseImpact: 8.0, ExposureClass: model.ExposureLocalhost, Confidence: model.ConfidenceHigh}
	if got := risk(mcp); got != 8.0 {
		t.Errorf("MCP finding risk = %v, want 8.0 (full weight)", got)
	}
	// Box-domain finding at localhost STILL gets the 0.10 discount (unchanged).
	box := model.Finding{Group: model.GroupHardening, BaseImpact: 9.0, ExposureClass: model.ExposureLocalhost, Confidence: model.ConfidenceHigh}
	if got := risk(box); got >= 1.0 {
		t.Errorf("box-domain localhost finding risk = %v, want ~0.9 (discount preserved)", got)
	}
}
