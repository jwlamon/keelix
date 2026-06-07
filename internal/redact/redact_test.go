package redact

import (
	"strings"
	"testing"
)

func TestRedactString(t *testing.T) {
	// Known secret values, as if pulled from a .env file.
	known := []string{"supersecretpw", "myapikey123"}
	r := newRedactor(known)

	tests := []struct {
		name        string
		in          string
		wantContain []string // substrings that MUST appear
		wantAbsent  []string // substrings that must NOT appear
	}{
		{
			name:        "known value redacted",
			in:          "POSTGRES_PASSWORD resolved to supersecretpw at runtime",
			wantContain: []string{"[REDACTED]", "POSTGRES_PASSWORD"},
			wantAbsent:  []string{"supersecretpw"},
		},
		{
			name:        "known value redacted everywhere it appears",
			in:          "db uses supersecretpw and cache also uses supersecretpw",
			wantContain: []string{"[REDACTED]"},
			wantAbsent:  []string{"supersecretpw"},
		},
		{
			name:        "postgres connection string password",
			in:          "DATABASE_URL=postgres://app:hunter2pass@db:5432/main",
			wantContain: []string{"postgres://app:[REDACTED]@db:5432/main"},
			wantAbsent:  []string{"hunter2pass"},
		},
		{
			name:        "generic user:pass@host",
			in:          "amqp://guest:s3kr1tRabbitPw@broker:5672",
			wantContain: []string{"amqp://guest:[REDACTED]@broker:5672"},
			wantAbsent:  []string{"s3kr1tRabbitPw"},
		},
		{
			name:        "bearer token",
			in:          "Authorization: Bearer abc123def456ghi789jkl012mno345",
			wantContain: []string{"Bearer [REDACTED]"},
			wantAbsent:  []string{"abc123def456ghi789jkl012mno345"},
		},
		{
			name:        "jwt",
			in:          "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
			wantContain: []string{"[REDACTED]"},
			wantAbsent:  []string{"eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
		},
		{
			name:        "high-entropy api key not in known set",
			in:          "key sk-live-Zx9Q2pL7mWvD3hKt8RnBuF1cYa6Es4Jg",
			wantContain: []string{"[REDACTED]"},
			wantAbsent:  []string{"sk-live-Zx9Q2pL7mWvD3hKt8RnBuF1cYa6Es4Jg"},
		},
		{
			name:        "ordinary low-entropy words untouched",
			in:          "PostgreSQL reachable from the internet on port 5432",
			wantContain: []string{"PostgreSQL reachable from the internet on port 5432"},
			wantAbsent:  []string{"[REDACTED]"},
		},
		{
			name:        "env key name is not redacted",
			in:          "POSTGRES_PASSWORD is set to a literal value in Compose",
			wantContain: []string{"POSTGRES_PASSWORD is set to a literal value in Compose"},
			wantAbsent:  []string{"[REDACTED]"},
		},
		{
			name:        "empty string",
			in:          "",
			wantContain: nil,
			wantAbsent:  []string{"[REDACTED]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.redactString(tt.in)
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("redactString(%q) = %q; want it to contain %q", tt.in, got, want)
				}
			}
			for _, bad := range tt.wantAbsent {
				if strings.Contains(got, bad) {
					t.Errorf("redactString(%q) = %q; must NOT contain %q", tt.in, got, bad)
				}
			}
		})
	}
}

func TestRedactStringShortKnownValueNotMatchedAsSubstringNoise(t *testing.T) {
	// A very short known value would cause noisy substring matches. We only
	// treat known values of >= 6 chars as redactable substrings.
	r := newRedactor([]string{"abc"})
	got := r.redactString("the alphabet abc is fine in fabric and abcissa")
	if strings.Contains(got, "[REDACTED]") {
		t.Errorf("short known value should not trigger substring redaction: %q", got)
	}
}

func TestShannonEntropy(t *testing.T) {
	low := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa")
	if low > 1.0 {
		t.Errorf("repeated char entropy should be ~0, got %v", low)
	}
	high := shannonEntropy("Zx9Q2pL7mWvD3hKt8RnBuF1c")
	if high < 3.5 {
		t.Errorf("random token entropy should be >= 3.5, got %v", high)
	}
}
