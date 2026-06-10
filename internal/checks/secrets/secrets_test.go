package secrets

import (
	"strings"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func stack(services ...*model.Service) *model.Stack {
	return &model.Stack{Services: services}
}

func svc(name string, env map[string]string) *model.Service {
	return &model.Service{Name: name, Environment: env}
}

// ---- Empty-stack NotAssessed (QF-1) ----

// TestSECCompose_EmptyStackNotAssessed verifies that SEC001/SEC003/SEC004 return
// NotAssessed (not a vacuous Pass) on an empty stack, so the grade is not inflated.
func TestSECCompose_EmptyStackNotAssessed(t *testing.T) {
	runners := []struct {
		id  string
		run func(*model.ScanContext) []model.Finding
	}{
		{"SEC001", func(ctx *model.ScanContext) []model.Finding { return (&sec001{}).Run(ctx) }},
		{"SEC003", func(ctx *model.ScanContext) []model.Finding { return (&sec003{}).Run(ctx) }},
		{"SEC004", func(ctx *model.ScanContext) []model.Finding { return (&sec004{}).Run(ctx) }},
	}
	for _, r := range runners {
		for _, ctx := range []*model.ScanContext{
			{},
			{Stack: &model.Stack{}},
		} {
			fs := r.run(ctx)
			if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
				t.Errorf("%s: want 1 NotAssessed finding on empty stack, got %+v", r.id, fs)
			}
		}
	}
}

// ---- SEC001 ----

func TestSEC001_LiteralFlagged(t *testing.T) {
	ctx := &model.ScanContext{Stack: stack(svc("db", map[string]string{
		"POSTGRES_PASSWORD": "supersecret",
	}))}
	findings := (&sec001{}).Run(ctx)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Errorf("expected failing finding, got pass")
	}
	// Ensure the secret value does not appear in evidence.
	if contains(f.Evidence, "supersecret") {
		t.Errorf("secret value must be redacted from evidence: %q", f.Evidence)
	}
	if f.Resource != "POSTGRES_PASSWORD" {
		t.Errorf("unexpected resource: %q", f.Resource)
	}
}

func TestSEC001_ReferenceNotFlagged(t *testing.T) {
	ctx := &model.ScanContext{Stack: stack(svc("db", map[string]string{
		"POSTGRES_PASSWORD": "${PG_PW}",
	}))}
	findings := (&sec001{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected a passing finding for reference value, got %+v", findings)
	}
}

func TestSEC001_NilStack(t *testing.T) {
	ctx := &model.ScanContext{Stack: nil}
	findings := (&sec001{}).Run(ctx)
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Errorf("expected NotAssessed for nil stack, got %+v", findings)
	}
}

func TestSEC001_EmptyServices(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	findings := (&sec001{}).Run(ctx)
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Errorf("expected NotAssessed for empty-services stack, got %+v", findings)
	}
}

// ---- SEC002 ----

func TestSEC002_CommittedEnv(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		EnvPath:      ".env",
		EnvCommitted: true,
	}}
	findings := (&sec002{}).Run(ctx)
	if len(findings) != 1 || findings[0].Passed {
		t.Errorf("expected one critical finding, got %+v", findings)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("expected critical severity, got %v", findings[0].Severity)
	}
}

func TestSEC002_NotCommitted(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		EnvPath:      ".env",
		EnvCommitted: false,
	}}
	findings := (&sec002{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass when env exists but not committed, got %+v", findings)
	}
}

func TestSEC002_NoEnv(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	findings := (&sec002{}).Run(ctx)
	if findings != nil {
		t.Errorf("expected nil when no env at all, got %+v", findings)
	}
}

// ---- SEC003 ----

func TestSEC003_WeakPasswordCritical(t *testing.T) {
	ctx := &model.ScanContext{Stack: stack(svc("db", map[string]string{
		"POSTGRES_PASSWORD": "admin",
	}))}
	findings := (&sec003{}).Run(ctx)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Errorf("expected failing finding")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected critical, got %v", f.Severity)
	}
	// The literal password value must not appear in output.
	if contains(f.Evidence, "admin") {
		t.Errorf("password value must be redacted: %q", f.Evidence)
	}
}

func TestSEC003_StrongPasswordPass(t *testing.T) {
	ctx := &model.ScanContext{Stack: stack(svc("db", map[string]string{
		"POSTGRES_PASSWORD": "V3ryStr0ng!Password#42",
	}))}
	findings := (&sec003{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass for strong password, got %+v", findings)
	}
}

func TestSEC003_ReferenceNotFlagged(t *testing.T) {
	ctx := &model.ScanContext{Stack: stack(svc("db", map[string]string{
		"POSTGRES_PASSWORD": "${DB_PW}",
	}))}
	findings := (&sec003{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass for reference, got %+v", findings)
	}
}

// ---- SEC004 ----

func TestSEC004_SecretLiteralNoDockerSecrets(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{svc("app", map[string]string{
			"API_KEY": "myapikey123",
		})},
		// No Secrets map -> len == 0
	}}
	findings := (&sec004{}).Run(ctx)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Passed {
		t.Errorf("expected failing finding")
	}
}

func TestSEC004_WithDockerSecrets(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{svc("app", map[string]string{
			"API_KEY": "myapikey123",
		})},
		Secrets: map[string]model.Secret{
			"api_key": {File: "./secrets/api_key.txt"},
		},
	}}
	findings := (&sec004{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass when docker secrets are in use, got %+v", findings)
	}
}

func TestSEC004_AtMostOnePerService(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{svc("app", map[string]string{
			"API_KEY":    "myapikey123",
			"API_SECRET": "mysecretval",
		})},
	}}
	findings := (&sec004{}).Run(ctx)
	// Count non-passing findings for "app"
	count := 0
	for _, f := range findings {
		if !f.Passed && f.Service == "app" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 SEC004 finding per service, got %d", count)
	}
}

func TestRedactedDescriptionNeverLeaksValue(t *testing.T) {
	secrets := []string{
		"hunter2",
		"password123",
		"S3cr3t-Db-Pass-With-Length",
		"admin",
		"",
	}
	for _, val := range secrets {
		got := redactedDescription(val)
		if val != "" && strings.Contains(got, val) {
			t.Errorf("redactedDescription(%q) = %q leaked the raw value", val, got)
		}
		// Allowed outputs only.
		switch {
		case got == "empty", got == "common default password":
			// ok
		case strings.HasPrefix(got, "too short ("):
			// ok
		default:
			t.Errorf("redactedDescription(%q) = %q is not one of the allowed redacted forms", val, got)
		}
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
