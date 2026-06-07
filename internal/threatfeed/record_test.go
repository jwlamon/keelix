package threatfeed

import "testing"

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := record{year: 2021, seq: 44228, flags: flagKEV | flagEPSS, pctl: 199}
	var buf [recordSize]byte
	encodeRecord(buf[:], in)
	got := decodeRecord(buf[:])
	if got != in {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, in)
	}
	if !got.kevListed() {
		t.Error("kevListed() = false, want true")
	}
	if !got.epssPresent() {
		t.Error("epssPresent() = false, want true")
	}
	if p := got.percentile(); p < 0.994 || p > 0.996 {
		t.Errorf("percentile() = %v, want ~0.995", p)
	}
}

func TestQuantizePercentile(t *testing.T) {
	cases := []struct {
		in   float64
		want uint8
	}{
		{-0.5, 0},
		{0, 0},
		{0.5, 100},
		{0.90, 180},
		{0.995, 199},
		{1.0, 200},
		{1.5, 200},
	}
	for _, c := range cases {
		if got := quantizePercentile(c.in); got != c.want {
			t.Errorf("quantizePercentile(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCmpKey(t *testing.T) {
	if cmpKey(2020, 5, 2021, 1) != -1 {
		t.Error("older year should sort first")
	}
	if cmpKey(2021, 9, 2021, 2) != 1 {
		t.Error("higher seq in same year should sort later")
	}
	if cmpKey(2021, 7, 2021, 7) != 0 {
		t.Error("equal keys should compare equal")
	}
}

// TestPercentileClamp verifies that pctl values > pctlBuckets (200) are clamped
// to 1.0 and never produce a weight exceeding 1.0 from a corrupted blob byte.
func TestPercentileClamp(t *testing.T) {
	cases := []struct {
		pctl uint8
		want float64
	}{
		{0, 0.0},
		{100, 0.5},
		{200, 1.0},
		{201, 1.0}, // corrupted: must clamp
		{255, 1.0}, // corrupted: must clamp
	}
	for _, c := range cases {
		r := record{pctl: c.pctl}
		got := r.percentile()
		if got != c.want {
			t.Errorf("record{pctl:%d}.percentile() = %v, want %v", c.pctl, got, c.want)
		}
		// Weight using only the EPSS path (not KEV) must also be <= 1.0.
		w := 0.3 + 0.7*got
		if w > 1.0 {
			t.Errorf("pctl=%d produces weight %v > 1.0", c.pctl, w)
		}
	}
}
