package score

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func cveFinding(cve string) model.Finding {
	return model.Finding{Metadata: map[string]string{"cve": cve}}
}

func TestThreatNoCVE(t *testing.T) {
	if got := threat(model.Finding{}); got != 1.0 {
		t.Errorf("threat(no metadata) = %v, want 1.0", got)
	}
	if got := threat(model.Finding{Metadata: map[string]string{}}); got != 1.0 {
		t.Errorf("threat(empty metadata) = %v, want 1.0", got)
	}
}

func TestThreatKEV(t *testing.T) {
	if got := threat(cveFinding("CVE-2021-44228")); got != 1.0 {
		t.Errorf("threat(Log4Shell KEV) = %v, want 1.0", got)
	}
}

func TestThreatHighEPSS(t *testing.T) {
	// CVE-1999-0001 (real blob, EPSS percentile 0.770, not KEV)
	// → 0.3 + 0.7*0.770 = 0.839.
	got := threat(cveFinding("CVE-1999-0001"))
	if got < 0.837 || got > 0.841 {
		t.Errorf("threat(high-EPSS CVE-1999-0001) = %v, want ~0.839", got)
	}
}

func TestThreatAbsentCVEFailsSafe(t *testing.T) {
	if got := threat(cveFinding("CVE-1971-0001")); got != 1.0 {
		t.Errorf("threat(absent CVE) = %v, want 1.0 (fail safe)", got)
	}
}
