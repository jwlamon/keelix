package redact

import (
	"strings"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestResultRedactsAllSpecFields(t *testing.T) {
	secret := "supersecretpw"
	apiKey := "Zx9Q2pL7mWvD3hKt8RnBuF1cYa6Es4Jg" // high entropy, not in env

	r := &model.Result{
		AISummary: "The database password supersecretpw is exposed.",
		Stack: &model.Stack{
			Env: map[string]string{
				"POSTGRES_PASSWORD": secret, // key looks secret -> value is known
				"LOG_LEVEL":         "debug",
			},
		},
		Findings: []model.Finding{
			{
				CheckID:  "SEC999",
				Title:    "leak in title supersecretpw",
				Detail:   "resolved to supersecretpw",
				Evidence: "DATABASE_URL=postgres://app:supersecretpw@db:5432/main",
				Resource: "value supersecretpw",
				Metadata: map[string]string{"raw": "token " + apiKey},
				Fix: model.Fix{
					Summary:  "rotate supersecretpw now",
					Diff:     "- PASS=supersecretpw\n+ PASS=${PG}",
					Commands: []string{"export PASS=supersecretpw"},
				},
			},
		},
		Probe: &model.ProbeResult{
			Reachable: map[int]model.PortProbe{
				6379: {Port: 6379, Open: true, Banner: "auth ok with supersecretpw"},
			},
		},
	}

	Result(r)

	// AISummary
	if strings.Contains(r.AISummary, secret) {
		t.Errorf("AISummary leaked: %q", r.AISummary)
	}
	f := r.Findings[0]
	for name, val := range map[string]string{
		"Title":      f.Title,
		"Detail":     f.Detail,
		"Evidence":   f.Evidence,
		"Resource":   f.Resource,
		"FixSummary": f.Fix.Summary,
		"FixDiff":    f.Fix.Diff,
	} {
		if strings.Contains(val, secret) {
			t.Errorf("%s leaked secret: %q", name, val)
		}
	}
	if strings.Contains(f.Fix.Commands[0], secret) {
		t.Errorf("Fix.Commands leaked: %q", f.Fix.Commands[0])
	}
	if strings.Contains(f.Metadata["raw"], apiKey) {
		t.Errorf("Metadata leaked high-entropy key: %q", f.Metadata["raw"])
	}
	// Connection-string form preserved with redacted password.
	if !strings.Contains(f.Evidence, "postgres://app:[REDACTED]@db:5432/main") {
		t.Errorf("connstring not redacted in place: %q", f.Evidence)
	}
	// Probe banner
	if strings.Contains(r.Probe.Reachable[6379].Banner, secret) {
		t.Errorf("probe banner leaked: %q", r.Probe.Reachable[6379].Banner)
	}
	// LOG_LEVEL=debug is NOT a secret key, so "debug" must survive elsewhere.
	if !strings.Contains(f.Fix.Diff, "${PG}") {
		t.Errorf("non-secret text should be preserved: %q", f.Fix.Diff)
	}
}

func TestResultNilSafe(t *testing.T) {
	Result(nil)             // must not panic
	Result(&model.Result{}) // no stack, no findings
}

func TestResultNoSecretEnvNoChange(t *testing.T) {
	r := &model.Result{
		Stack:    &model.Stack{Env: map[string]string{"LOG_LEVEL": "debug"}},
		Findings: []model.Finding{{Detail: "PostgreSQL reachable on port 5432"}},
	}
	Result(r)
	if r.Findings[0].Detail != "PostgreSQL reachable on port 5432" {
		t.Errorf("clean finding was modified: %q", r.Findings[0].Detail)
	}
}
