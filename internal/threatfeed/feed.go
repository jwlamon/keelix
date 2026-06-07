package threatfeed

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// blobGz is the gzipped, fixed-width, (year,seq)-sorted threatfeed table.
// Generated at release time by internal/threatfeed/gen; CI uses it as-is.
//
//go:embed data/threatfeed.bin.gz
var blobGz []byte

// staleAfter is the age past which IsStale reports true.
const staleAfter = 30 * 24 * time.Hour

// table holds the decompressed records and is built exactly once.
type tableState struct {
	recs []record
	err  error
}

var (
	loadOnce sync.Once
	loaded   tableState
)

// load decompresses blobGz into a sorted []record exactly once. On error the
// table is left empty and all lookups fail safe (KEVListed=false, EPSS absent,
// Weight=1.0). It never panics so a corrupt blob degrades, not crashes.
func load() tableState {
	loadOnce.Do(func() {
		gr, err := gzip.NewReader(bytes.NewReader(blobGz))
		if err != nil {
			loaded = tableState{err: err}
			return
		}
		defer gr.Close()
		raw, err := io.ReadAll(gr)
		if err != nil {
			loaded = tableState{err: err}
			return
		}
		if len(raw)%recordSize != 0 {
			loaded = tableState{err: fmt.Errorf("threatfeed: decompressed length %d not a multiple of record size %d", len(raw), recordSize)}
			return
		}
		n := len(raw) / recordSize
		recs := make([]record, 0, n)
		for i := 0; i+recordSize <= len(raw); i += recordSize {
			recs = append(recs, decodeRecord(raw[i:i+recordSize]))
		}
		loaded = tableState{recs: recs}
	})
	return loaded
}

// lookup binary-searches the table for (year,seq). ok is false when absent.
func lookup(cve string) (record, bool) {
	y, s, ok := parseCVE(cve)
	if !ok {
		return record{}, false
	}
	st := load()
	if st.err != nil || len(st.recs) == 0 {
		return record{}, false
	}
	i := sort.Search(len(st.recs), func(i int) bool {
		return cmpKey(st.recs[i].year, st.recs[i].seq, y, s) >= 0
	})
	if i < len(st.recs) && st.recs[i].year == y && st.recs[i].seq == s {
		return st.recs[i], true
	}
	return record{}, false
}

// KEVListed reports whether the CVE is on the CISA KEV (known-exploited) list.
// Malformed or absent CVEs return false.
func KEVListed(cve string) bool {
	r, ok := lookup(cve)
	return ok && r.kevListed()
}

// EPSSPercentile returns the EPSS exploit-prediction percentile in [0,1] for the
// CVE, and ok=true only when an EPSS percentile is present. Absent/malformed
// CVEs, and CVEs that are KEV-only with no EPSS row, return (0, false).
func EPSSPercentile(cve string) (float64, bool) {
	r, ok := lookup(cve)
	if !ok || !r.epssPresent() {
		return 0, false
	}
	return r.percentile(), true
}

// EPSSBucket returns the raw quantized EPSS bucket (0–200) for the CVE and
// ok=true when an EPSS percentile is present. The bucket is the integer
// representation used internally: percentile = bucket/200. Comparisons in
// bucket space avoid floating-point rounding artifacts at threshold boundaries
// (e.g. bucket 181 is the first bucket strictly above 0.90).
// Absent/malformed CVEs, and CVEs that are KEV-only with no EPSS row, return (0, false).
func EPSSBucket(cve string) (uint8, bool) {
	r, ok := lookup(cve)
	if !ok || !r.epssPresent() {
		return 0, false
	}
	p := r.pctl
	if p > pctlBuckets {
		p = pctlBuckets
	}
	return p, true
}

// Weight returns the exploitability weight for a CVE in [0.3,1.0]:
//   - KEV-listed                 → 1.0 (strongest "patch now" signal)
//   - EPSS percentile p present  → 0.3 + 0.7*p   (range [0.3,1.0])
//   - otherwise (absent/malformed) → 1.0 (fail safe to full weight)
//
// This mirrors score.threat() exactly; the score engine calls KEVListed/
// EPSSPercentile directly, but Weight is exported for tests and callers that
// want the composed value.
func Weight(cve string) float64 {
	r, ok := lookup(cve)
	if !ok {
		return 1.0
	}
	if r.kevListed() {
		return 1.0
	}
	if r.epssPresent() {
		return 0.3 + 0.7*r.percentile()
	}
	return 1.0
}

// SnapshotDate returns the UTC date the embedded blob was generated. A malformed
// snapshotDateRaw (should never happen — it is generated) yields the zero time,
// which makes IsStale report true (fail toward warning).
func SnapshotDate() time.Time {
	t, err := time.Parse("2006-01-02", snapshotDateRaw)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// IsStale reports whether the snapshot is older than 30 days relative to the
// caller-injected now. now is always passed in; this package never reads the
// wall clock itself.
func IsStale(now time.Time) bool {
	return now.UTC().Sub(SnapshotDate()) > staleAfter
}
