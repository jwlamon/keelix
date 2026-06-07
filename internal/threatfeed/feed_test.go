package threatfeed

import (
	"bytes"
	"compress/gzip"
	"sync"
	"testing"
	"time"
)

// TestEmbeddedBlobStructuralInvariants verifies the committed blob meets all
// structural requirements: decompresses without error, record count floor,
// sorted order, pctl bounds, and KEV count floor.
func TestEmbeddedBlobStructuralInvariants(t *testing.T) {
	st := load()
	if st.err != nil {
		t.Fatalf("load() error: %v", st.err)
	}

	// Record-count floor: prevent a fixture-only blob from ever shipping.
	const recordFloor = 100_000
	if len(st.recs) < recordFloor {
		t.Fatalf("embedded blob has %d records, want >= %d (fixture-only blob?)", len(st.recs), recordFloor)
	}

	// Table must be strictly sorted ascending by (year, seq).
	for i := 1; i < len(st.recs); i++ {
		if cmpKey(st.recs[i-1].year, st.recs[i-1].seq, st.recs[i].year, st.recs[i].seq) > 0 {
			t.Fatalf("table not sorted at index %d: %+v then %+v", i, st.recs[i-1], st.recs[i])
		}
	}

	// Every pctl must be <= 200 (pctlBuckets); values > 200 produce weight > 1.0.
	for i, r := range st.recs {
		if r.pctl > pctlBuckets {
			t.Errorf("record[%d] pctl=%d exceeds pctlBuckets=%d", i, r.pctl, pctlBuckets)
		}
	}

	// KEV-listed count floor: real CISA KEV has 1,600+ entries.
	kevCount := 0
	for _, r := range st.recs {
		if r.kevListed() {
			kevCount++
		}
	}
	const kevFloor = 1_000
	if kevCount < kevFloor {
		t.Errorf("blob has %d KEV-listed records, want >= %d", kevCount, kevFloor)
	}
}

// TestEmbeddedBlobDecompresses is kept for backwards-compat; structural
// invariants are now covered by TestEmbeddedBlobStructuralInvariants.
func TestEmbeddedBlobDecompresses(t *testing.T) {
	st := load()
	if st.err != nil {
		t.Fatalf("load() error: %v", st.err)
	}
	if len(st.recs) == 0 {
		t.Fatal("decompressed table is empty")
	}
}

func TestKEVListed_RealBlob(t *testing.T) {
	// Persistent KEV CVEs that must always be listed.
	if !KEVListed("CVE-2021-44228") {
		t.Error("CVE-2021-44228 (Log4Shell) should be KEV-listed")
	}
	if !KEVListed("CVE-2014-0160") {
		t.Error("CVE-2014-0160 (Heartbleed) should be KEV-listed")
	}
	// CVE-1999-0001 is present with EPSS but is NOT on the KEV list.
	if KEVListed("CVE-1999-0001") {
		t.Error("CVE-1999-0001 should NOT be KEV-listed")
	}
	// CVE-1980-0001 is absent from the blob entirely.
	if KEVListed("CVE-1980-0001") {
		t.Error("CVE-1980-0001 (absent) should not be KEV-listed")
	}
	if KEVListed("not-a-cve") {
		t.Error("malformed CVE should not be KEV-listed")
	}
}

func TestEPSSPercentile_RealBlob(t *testing.T) {
	// CVE-1999-0001: present with EPSS percentile ~0.770 (pctl=154, 154/200=0.77).
	p, ok := EPSSPercentile("CVE-1999-0001")
	if !ok {
		t.Fatal("CVE-1999-0001 should have an EPSS percentile")
	}
	// Exact quantized value: pctl=154 → 154/200 = 0.770.
	if p < 0.765 || p > 0.775 {
		t.Errorf("CVE-1999-0001 percentile = %v, want ~0.770", p)
	}
	// CVE-1980-0001: absent from the blob → no EPSS.
	if _, ok := EPSSPercentile("CVE-1980-0001"); ok {
		t.Error("CVE-1980-0001 (absent) should report no EPSS percentile")
	}
	// Malformed input → no EPSS.
	if _, ok := EPSSPercentile("not-a-cve"); ok {
		t.Error("malformed CVE should report no EPSS percentile")
	}
}

// TestEPSSBucket_RealBlob verifies EPSSBucket returns the raw integer bucket
// and correctly discriminates at the SUP004 threshold boundary.
//
// The threshold is bucket 181: the first bucket strictly above 0.90 at 1/200
// quantization resolution. Bucket 180 decodes to exactly 0.90 (180/200=0.900),
// so a float comparison "p >= 0.90" would treat pctl=180 as meeting the
// threshold — a false positive for CVEs whose true EPSS is just below 0.90.
// Bucket-space comparison avoids this: 180 < 181 → does not fire.
//
// CVE pctl values (persistent, 2026-06-05 snapshot):
//   - CVE-1999-186:   pctl=180 (boundary below threshold)
//   - CVE-1999-42:    pctl=181 (first bucket above threshold)
//   - CVE-2022-42889: pctl=200 (Text4Shell, high-EPSS non-KEV fixture)
//   - CVE-2021-44228: pctl=200, KEV+EPSS (Log4Shell; SUP004 skips via KEVListed)
func TestEPSSBucket_RealBlob(t *testing.T) {
	const bucketThreshold = uint8(181) // mirrors sup004EPSSBucketThreshold

	bucketCases := []struct {
		cve      string
		wantOK   bool
		wantPctl uint8
		note     string
	}{
		{"CVE-1999-186", true, 180, "pctl=180, boundary below threshold"},
		{"CVE-1999-42", true, 181, "pctl=181, first bucket above threshold"},
		{"CVE-2022-42889", true, 200, "Text4Shell, pctl=200"},
		{"CVE-2021-44228", true, 200, "Log4Shell KEV+EPSS, pctl=200"},
		{"CVE-1980-0001", false, 0, "absent CVE"},
		{"not-a-cve", false, 0, "malformed CVE"},
	}
	for _, tc := range bucketCases {
		b, ok := EPSSBucket(tc.cve)
		if ok != tc.wantOK {
			t.Errorf("%s (%s): EPSSBucket ok=%v, want %v", tc.cve, tc.note, ok, tc.wantOK)
			continue
		}
		if ok && b != tc.wantPctl {
			t.Errorf("%s (%s): EPSSBucket=%d, want %d", tc.cve, tc.note, b, tc.wantPctl)
		}
	}

	// Boundary: pctl=180 must be BELOW threshold; pctl=181 must be AT threshold.
	b180, ok180 := EPSSBucket("CVE-1999-186")
	if !ok180 {
		t.Fatal("CVE-1999-186 (pctl=180) must have an EPSS bucket")
	}
	if b180 >= bucketThreshold {
		t.Errorf("CVE-1999-186 pctl=%d must be below SUP004 threshold %d (false-positive boundary)", b180, bucketThreshold)
	}

	b181, ok181 := EPSSBucket("CVE-1999-42")
	if !ok181 {
		t.Fatal("CVE-1999-42 (pctl=181) must have an EPSS bucket")
	}
	if b181 < bucketThreshold {
		t.Errorf("CVE-1999-42 pctl=%d must meet SUP004 threshold %d", b181, bucketThreshold)
	}
}

func TestWeight_RealBlob(t *testing.T) {
	// KEV CVEs → Weight 1.0.
	if w := Weight("CVE-2021-44228"); w != 1.0 {
		t.Errorf("CVE-2021-44228 (Log4Shell KEV) weight = %v, want 1.0", w)
	}
	if w := Weight("CVE-2014-0160"); w != 1.0 {
		t.Errorf("CVE-2014-0160 (Heartbleed KEV) weight = %v, want 1.0", w)
	}
	// CVE-1999-0001: EPSS ~0.770 → Weight = 0.3 + 0.7*0.770 = 0.839.
	if w := Weight("CVE-1999-0001"); w < 0.835 || w > 0.843 {
		t.Errorf("CVE-1999-0001 weight = %v, want ~0.839", w)
	}
	// CVE-1980-0001: absent → fail safe to 1.0.
	if w := Weight("CVE-1980-0001"); w != 1.0 {
		t.Errorf("CVE-1980-0001 (absent) weight = %v, want 1.0", w)
	}
	// Malformed → fail safe to 1.0.
	if w := Weight(""); w != 1.0 {
		t.Errorf("empty CVE weight = %v, want 1.0", w)
	}
}

// TestBlobAlignmentGuard verifies that a truncated (non-multiple-of-8) blob
// is rejected as a hard error rather than silently losing the trailing record.
func TestBlobAlignmentGuard(t *testing.T) {
	// Build a minimal valid blob: two valid records, then truncate by 3 bytes.
	r0 := record{year: 2021, seq: 44228, flags: flagKEV | flagEPSS, pctl: 200}
	r1 := record{year: 2023, seq: 3519, flags: flagKEV | flagEPSS, pctl: 200}
	raw := make([]byte, 2*recordSize)
	encodeRecord(raw[0:recordSize], r0)
	encodeRecord(raw[recordSize:2*recordSize], r1)
	truncated := raw[:2*recordSize-3] // not a multiple of 8

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write(truncated)
	_ = gw.Close()

	// Swap in the truncated blob and reset the singleton so load() re-runs.
	origBlob := blobGz
	blobGz = buf.Bytes()
	loadOnce = sync.Once{}
	loaded = tableState{}

	st := load()

	// Restore the real blob and re-initialize the singleton for subsequent tests.
	blobGz = origBlob
	loadOnce = sync.Once{}
	loaded = tableState{}
	_ = load() // re-populate with the real blob

	if st.err == nil {
		t.Error("expected error for non-multiple-of-8 blob length, got nil")
	}
}

func TestSnapshotDateAndStaleness(t *testing.T) {
	d := SnapshotDate()
	if d.IsZero() {
		t.Fatal("SnapshotDate parsed to zero time; snapshotDateRaw malformed")
	}
	// One day after snapshot → not stale.
	if IsStale(d.Add(24 * time.Hour)) {
		t.Error("1 day old should not be stale")
	}
	// 31 days after snapshot → stale.
	if !IsStale(d.Add(31 * 24 * time.Hour)) {
		t.Error("31 days old should be stale")
	}
	// Exactly 30 days → boundary, not yet stale (> not >=).
	if IsStale(d.Add(30 * 24 * time.Hour)) {
		t.Error("exactly 30 days should not be stale")
	}
}
