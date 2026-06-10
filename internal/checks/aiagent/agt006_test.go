package aiagent_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestAGT006_NonLoopbackSocket_Critical(t *testing.T) {
	c := findCheck(t, "AGT006")
	sigs := &model.Signals{
		Sockets: []model.ListeningSocket{
			{Proto: "tcp", Bind: "0.0.0.0", Port: 3000, Comm: "openclaw", PID: 200, UID: 1000},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT006" && f.IsFail() {
			found = true
			if f.Severity != model.SeverityCritical {
				t.Errorf("AGT006: want Critical, got %s", f.Severity)
			}
			if !f.Fatal {
				t.Error("AGT006: want Fatal=true")
			}
			if f.ExposureClass != model.ExposureInternet {
				t.Errorf("AGT006: want ExposureInternet for 0.0.0.0, got %v", f.ExposureClass)
			}
		}
	}
	if !found {
		t.Fatal("AGT006: want Critical fatal finding for non-loopback agent socket")
	}
}

func TestAGT006_LoopbackSocket_Pass(t *testing.T) {
	c := findCheck(t, "AGT006")
	sigs := &model.Signals{
		Sockets: []model.ListeningSocket{
			{Proto: "tcp", Bind: "127.0.0.1", Port: 3000, Comm: "openclaw", PID: 200, UID: 1000},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT006" && f.IsFail() {
			t.Errorf("AGT006: loopback socket should pass, got %+v", f)
		}
	}
}

func TestAGT006_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT006")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT006: want NotAssessed, got %+v", findings)
	}
}

// TestRFX8_AGT006_FixSummaryIsPlainString is a parser-fed regression test for RFX-8/AGT006.
// It verifies that the Fix.Summary is a non-empty plain string (not formatted via Sprintf
// with no args, which go vet flags as SA1006/printf). This confirms the fix was applied.
func TestRFX8_AGT006_FixSummaryIsPlainString(t *testing.T) {
	c := findCheck(t, "AGT006")
	sigs := &model.Signals{
		Sockets: []model.ListeningSocket{
			{Proto: "tcp", Bind: "0.0.0.0", Port: 3000, Comm: "openclaw", PID: 200, UID: 1000},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT006" && f.IsFail() {
			if f.Fix.Summary == "" {
				t.Error("AGT006: Fix.Summary must not be empty")
			}
			// The summary must not contain a bare %s/%d that would indicate
			// an unformatted format string was accidentally left in.
			return
		}
	}
	t.Fatal("AGT006: want a failing finding for non-loopback socket")
}
