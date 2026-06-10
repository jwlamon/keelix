package redact

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
	"github.com/jakelamon/keelix/internal/report"
)

// TestResultRedactsCollector verifies that redact.Result scrubs every
// secret-bearing free-text field in result.Collector (the Signals document)
// so that the token never appears in the JSON output of report.JSON.
func TestResultRedactsCollector(t *testing.T) {
	// High-entropy standalone token (32 chars, high Shannon entropy).
	secret := "Zx9Q2pL7mWvD3hKt8RnBuF1cYa6Es4Jg"

	r := &model.Result{
		Collector: &model.Signals{
			Configs: []model.ConfigFact{
				{
					Source:   "/etc/app/config.env",
					SchemaID: "dotenv",
					Values:   map[string]string{"DB_PASSWORD": secret},
				},
			},
			Firewall: model.FirewallState{
				Backend: "ufw",
				Rules:   []string{"allow from 0.0.0.0 token=" + secret},
			},
			Processes: []model.ProcessFact{
				{
					Comm: "app",
					PID:  1234,
					Args: []string{"--api-key=" + secret, "--port=8080"},
				},
			},
			Errors: []model.CollectError{
				{
					Domain: "config",
					Err:    "failed to decrypt " + secret,
				},
			},
		},
	}

	Result(r)

	// Direct struct checks.
	cfg := r.Collector.Configs[0]
	if strings.Contains(cfg.Values["DB_PASSWORD"], secret) {
		t.Errorf("ConfigFact.Values leaked: %q", cfg.Values["DB_PASSWORD"])
	}
	if !strings.Contains(cfg.Values["DB_PASSWORD"], marker) {
		t.Errorf("ConfigFact.Values not redacted: %q", cfg.Values["DB_PASSWORD"])
	}

	fwRule := r.Collector.Firewall.Rules[0]
	if strings.Contains(fwRule, secret) {
		t.Errorf("Firewall.Rules leaked: %q", fwRule)
	}
	if !strings.Contains(fwRule, marker) {
		t.Errorf("Firewall.Rules not redacted: %q", fwRule)
	}

	procArg := r.Collector.Processes[0].Args[0]
	if strings.Contains(procArg, secret) {
		t.Errorf("ProcessFact.Args leaked: %q", procArg)
	}
	if !strings.Contains(procArg, marker) {
		t.Errorf("ProcessFact.Args not redacted: %q", procArg)
	}

	colErr := r.Collector.Errors[0]
	if strings.Contains(colErr.Err, secret) {
		t.Errorf("CollectError.Err leaked: %q", colErr.Err)
	}
	if !strings.Contains(colErr.Err, marker) {
		t.Errorf("CollectError.Err not redacted: %q", colErr.Err)
	}

	// Serialize via report.JSON and assert the secret is absent from the wire format.
	var buf bytes.Buffer
	if err := report.JSON(&buf, r); err != nil {
		t.Fatalf("report.JSON error: %v", err)
	}
	if strings.Contains(buf.String(), secret) {
		t.Errorf("secret leaked into JSON output")
	}
}

// The redactor must scrub a token-shaped secret out of CapDriver.Reason and out
// of NotAssessed findings (Evidence + Mitigations), not just Result.Findings.
func TestResultRedactsV2Surfaces(t *testing.T) {
	apiKey := "Zx9Q2pL7mWvD3hKt8RnBuF1cYa6Es4Jg" // high-entropy standalone token

	r := &model.Result{
		CapDriver: &model.CapDriver{
			CheckID: "EXP001",
			Title:   "Postgres exposed",
			Reason:  "capped RED because token " + apiKey + " confirmed open",
			Grade:   "RED",
		},
		NotAssessed: []model.Finding{
			{
				CheckID:     "HRD009",
				Evidence:    "could not read token " + apiKey,
				Mitigations: []string{"behind proxy using " + apiKey},
				Status:      model.StatusNotAssessed,
			},
		},
	}

	Result(r)

	if strings.Contains(r.CapDriver.Reason, apiKey) {
		t.Errorf("CapDriver.Reason leaked: %q", r.CapDriver.Reason)
	}
	if !strings.Contains(r.CapDriver.Reason, marker) {
		t.Errorf("CapDriver.Reason not redacted: %q", r.CapDriver.Reason)
	}
	na := r.NotAssessed[0]
	if strings.Contains(na.Evidence, apiKey) {
		t.Errorf("NotAssessed Evidence leaked: %q", na.Evidence)
	}
	if strings.Contains(na.Mitigations[0], apiKey) {
		t.Errorf("NotAssessed Mitigations leaked: %q", na.Mitigations[0])
	}
}
