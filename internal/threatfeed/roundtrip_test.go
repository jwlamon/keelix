package threatfeed

import "testing"

// TestGeneratorBlobRoundTrip asserts the committed (generator-produced) blob
// resolves all four EPSS/KEV combinations through the public reader API using
// persistent real CVEs that survive any blob regeneration from the real feeds.
func TestGeneratorBlobRoundTrip(t *testing.T) {
	// KEV + EPSS present (Log4Shell): KEV wins → Weight 1.0.
	if !KEVListed("CVE-2021-44228") {
		t.Error("CVE-2021-44228 (Log4Shell) should be KEV")
	}
	if w := Weight("CVE-2021-44228"); w != 1.0 {
		t.Errorf("CVE-2021-44228 weight = %v, want 1.0", w)
	}

	// KEV + EPSS present (Heartbleed): KEV wins → Weight 1.0.
	if !KEVListed("CVE-2014-0160") {
		t.Error("CVE-2014-0160 (Heartbleed) should be KEV")
	}
	if w := Weight("CVE-2014-0160"); w != 1.0 {
		t.Errorf("CVE-2014-0160 weight = %v, want 1.0", w)
	}

	// EPSS-present, non-KEV (CVE-1999-0001): percentile ~0.770, weight ~0.839.
	if KEVListed("CVE-1999-0001") {
		t.Error("CVE-1999-0001 should NOT be KEV")
	}
	p, ok := EPSSPercentile("CVE-1999-0001")
	if !ok {
		t.Fatal("CVE-1999-0001 should have an EPSS percentile")
	}
	// Quantized to pctl=154 → 154/200=0.770; allow ±0.01 for future EPSS updates.
	if p < 0.760 || p > 0.780 {
		t.Errorf("CVE-1999-0001 percentile = %.4f, want ~0.770", p)
	}
	if w := Weight("CVE-1999-0001"); w < 0.830 || w > 0.848 {
		t.Errorf("CVE-1999-0001 weight = %.4f, want ~0.839", w)
	}

	// Absent CVE (CVE-1980-0001): not in any real feed → fail safe Weight=1.0.
	if KEVListed("CVE-1980-0001") {
		t.Error("CVE-1980-0001 (absent) should NOT be KEV")
	}
	if _, ok := EPSSPercentile("CVE-1980-0001"); ok {
		t.Error("CVE-1980-0001 (absent) should have NO EPSS percentile")
	}
	if w := Weight("CVE-1980-0001"); w != 1.0 {
		t.Errorf("CVE-1980-0001 (absent) weight = %v, want 1.0 (fail-safe)", w)
	}
}
