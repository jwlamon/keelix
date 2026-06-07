package main

import (
	"os"
	"strings"
	"testing"
)

func TestBuildTableUnion(t *testing.T) {
	epss, err := os.Open("testdata/epss_sample.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer epss.Close()
	kev, err := os.Open("testdata/kev_sample.json")
	if err != nil {
		t.Fatal(err)
	}
	defer kev.Close()

	recs, err := buildTable(epss, kev)
	if err != nil {
		t.Fatalf("buildTable: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("empty table")
	}

	// Sorted ascending.
	for i := 1; i < len(recs); i++ {
		if recs[i-1].year > recs[i].year ||
			(recs[i-1].year == recs[i].year && recs[i-1].seq > recs[i].seq) {
			t.Fatalf("not sorted at %d", i)
		}
	}

	find := func(y uint16, s uint32) (genRecord, bool) {
		for _, r := range recs {
			if r.year == y && r.seq == s {
				return r, true
			}
		}
		return genRecord{}, false
	}

	// Log4Shell: KEV + EPSS, pctl 200.
	if r, ok := find(2021, 44228); !ok {
		t.Error("CVE-2021-44228 missing")
	} else {
		if r.flags&genFlagKEV == 0 || r.flags&genFlagEPSS == 0 {
			t.Errorf("CVE-2021-44228 flags = %b, want KEV+EPSS", r.flags)
		}
		if r.pctl != 200 {
			t.Errorf("CVE-2021-44228 pctl = %d, want 200", r.pctl)
		}
	}

	// KEV-only (CVE-2023-3519): KEV set, EPSS clear, pctl 0.
	if r, ok := find(2023, 3519); !ok {
		t.Error("CVE-2023-3519 missing")
	} else {
		if r.flags&genFlagKEV == 0 {
			t.Error("CVE-2023-3519 should be KEV")
		}
		if r.flags&genFlagEPSS != 0 {
			t.Error("CVE-2023-3519 should NOT have EPSS flag")
		}
	}

	// EPSS-only high (CVE-2099-99999): EPSS set, KEV clear, pctl 190.
	if r, ok := find(2099, 99999); !ok {
		t.Error("CVE-2099-99999 missing")
	} else {
		if r.flags&genFlagEPSS == 0 || r.flags&genFlagKEV != 0 {
			t.Errorf("CVE-2099-99999 flags = %b, want EPSS-only", r.flags)
		}
		if r.pctl != 190 {
			t.Errorf("CVE-2099-99999 pctl = %d, want 190", r.pctl)
		}
	}
}

// TestNoGoGenerateDirective verifies that build.go does NOT contain an active
// go:generate directive that would silently overwrite the production blob
// with fixture data when a developer runs `go generate ./...`.
// The real release command is documented in the package comment; go:generate
// must stay absent. We detect the directive by looking for a line that starts
// with "//go:generate" (the exact form the go tool recognises).
func TestNoGoGenerateDirective(t *testing.T) {
	data, err := os.ReadFile("build.go")
	if err != nil {
		t.Fatalf("read build.go: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//go:generate") {
			t.Errorf("build.go line %q is an active //go:generate directive that would overwrite the production blob with fixtures; remove it", line)
		}
	}
}

func TestSnapshotSource(t *testing.T) {
	src := snapshotSource("2026-06-05")
	if !strings.Contains(src, `const snapshotDateRaw = "2026-06-05"`) {
		t.Errorf("snapshot source missing date constant:\n%s", src)
	}
	if !strings.Contains(src, "DO NOT EDIT") {
		t.Error("snapshot source missing generated marker")
	}
}

func TestParseCVEKey(t *testing.T) {
	if y, s, ok := parseCVEKey("CVE-2014-0160"); !ok || y != 2014 || s != 160 {
		t.Errorf("parseCVEKey heartbleed = (%d,%d,%v)", y, s, ok)
	}
	if _, _, ok := parseCVEKey("garbage"); ok {
		t.Error("garbage should not parse")
	}
}
