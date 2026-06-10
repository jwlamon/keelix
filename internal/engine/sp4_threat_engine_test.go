package engine

import (
	"context"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// TestSP4_KEVImageCapsRED runs a full scan over a stack whose image maps to a
// known-exploited (KEV) CVE, published to all interfaces. The box must be capped
// RED with SUP003 as the cap driver — proving threatfeed + intel + SUP003 +
// applyKEVFatal + the network RED cap are wired end-to-end.
func TestSP4_KEVImageCapsRED(t *testing.T) {
	in := Input{
		ComposePath: "testdata/sp4_kev_compose.yml",
		Options: model.ScanOptions{
			NoProbe: true,
			Host:    "", // static analysis only
		},
	}
	res, err := Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Rating != "RED" {
		t.Errorf("rating = %q, want RED (KEV image published to all interfaces)", res.Rating)
	}
	if res.CapDriver == nil || res.CapDriver.CheckID != "SUP003" {
		t.Errorf("cap driver = %+v, want SUP003 RED cap", res.CapDriver)
	}
	// The SUP003 finding must carry the CVE in metadata.
	var found bool
	for _, f := range res.Findings {
		if f.CheckID == "SUP003" && !f.Passed {
			found = true
			if f.Metadata["cve"] != "CVE-2021-44228" {
				t.Errorf("SUP003 Metadata[cve] = %q, want CVE-2021-44228", f.Metadata["cve"])
			}
		}
	}
	if !found {
		t.Error("no failing SUP003 finding in result")
	}
}

// TestSP4_KEVImageLoopbackNoRED verifies that a KEV image bound only to localhost
// (127.0.0.1) does NOT cap the overall rating to RED. Localhost-only services
// cannot be reached from the network, so applyKEVFatal must NOT escalate the
// finding — the spec reads "KEV on a localhost-only service stays a high-weight
// non-fatal contributor". The SUP003 finding may still be present, but it must
// NOT be the cap driver for a RED rating.
func TestSP4_KEVImageLoopbackNoRED(t *testing.T) {
	in := Input{
		ComposePath: "testdata/sp4_kev_loopback_compose.yml",
		Options: model.ScanOptions{
			NoProbe: true,
			Host:    "", // static analysis only
		},
	}
	res, err := Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if res.Rating == "RED" {
		t.Errorf("rating = RED, want non-RED (KEV image on localhost-only binding must not cap RED)")
	}
	// If there is a cap driver it must NOT be SUP003 driving a RED.
	if res.CapDriver != nil && res.CapDriver.CheckID == "SUP003" && res.CapDriver.Grade == "RED" {
		t.Errorf("cap driver = SUP003/RED on a localhost-only image — applyKEVFatal must not escalate loopback findings")
	}
}

// TestSP4_EPSSHighImageFiresSUP004 verifies that a stack whose image maps to a
// high-EPSS (non-KEV) CVE fires SUP004 at Warning severity and does NOT cap the
// rating to RED. This exercises the SUP004 path end-to-end through the engine,
// confirming that high-EPSS alone is flagged but not treated as a fatal network
// exposure.
func TestSP4_EPSSHighImageFiresSUP004(t *testing.T) {
	in := Input{
		ComposePath: "testdata/sp4_epss_compose.yml",
		Options: model.ScanOptions{
			NoProbe: true,
			Host:    "", // static analysis only
		},
	}
	res, err := Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// SUP004 must fire (Warning, not Fatal → no RED cap from it).
	var sup004Found bool
	for _, f := range res.Findings {
		if f.CheckID == "SUP004" && !f.Passed {
			sup004Found = true
			if f.Severity != model.SeverityWarning {
				t.Errorf("SUP004 severity = %v, want Warning", f.Severity)
			}
			if f.Fatal {
				t.Error("SUP004 finding must not be Fatal")
			}
			if f.Metadata["cve"] != "CVE-2022-42889" {
				t.Errorf("SUP004 Metadata[cve] = %q, want CVE-2022-42889", f.Metadata["cve"])
			}
		}
	}
	if !sup004Found {
		t.Error("no failing SUP004 finding in result for high-EPSS image")
	}

	// A high-EPSS-only image must NOT drive a RED cap through the network cap
	// path (SUP004 is Warning/non-Fatal, not a Fatal KEV critical).
	if res.Rating == "RED" && res.CapDriver != nil && res.CapDriver.CheckID == "SUP004" {
		t.Errorf("SUP004 drove a RED cap — high-EPSS non-KEV findings must not cap RED")
	}
}
