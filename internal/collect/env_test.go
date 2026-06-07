package collect

import (
	"path/filepath"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestClassifyEnv(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  string // EnvShape.Class
	}{
		{"empty value", "DEBUG", "", "empty"},
		{"name match TOKEN", "GITHUB_TOKEN", "x", "secret"},
		{"name match API_KEY", "API_KEY", "abc", "secret"},
		{"name match SECRET", "DB_SECRET", "abc", "secret"},
		{"name match PASSWORD", "POSTGRES_PASSWORD", "hunter2", "secret"},
		{"name match lowercase password", "db_password", "hunter2", "secret"},
		{"high entropy value", "RANDOM", "Hb7Qx2Vp9LmZ4Kt8RwN3Yc6Fd1Js5Gu", "secret"},
		{"path absolute", "DATA_DIR", "/var/lib/app", "path"},
		{"path relative with slash", "CONFIG", "./config/app.yml", "path"},
		{"plain word", "ENVIRONMENT", "production", "plain"},
		{"plain number", "PORT", "5432", "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyEnv(tt.key, tt.value)
			if got.Name != tt.key {
				t.Errorf("Name = %q, want %q", got.Name, tt.key)
			}
			if got.Class != tt.want {
				t.Errorf("classifyEnv(%q, <redacted>).Class = %q, want %q", tt.key, got.Class, tt.want)
			}
		})
	}
}

func TestClassifyEnvNeverStoresValue(t *testing.T) {
	const secret = "super-secret-value-12345"
	got := classifyEnv("PASSWORD", secret)
	// EnvShape has only Name and Class fields — assert the secret never appears.
	if got.Name == secret || got.Class == secret {
		t.Fatalf("classifyEnv stored the raw value: %+v", got)
	}
	var _ model.EnvShape = got // compile-time: returns the contract type
}

// TestWebhookURLRedactionParserFed is a parser-fed regression test for FIX-8.
// It commits a .env fixture that contains a high-entropy Slack webhook URL under
// the key WEBHOOK_URL (whose name does NOT match any secretNameToken), then runs
// the full collect parse->redact pipeline via collectConfigInternal so that the
// real entropy gate and redaction path are exercised — NOT a synthetic hand-built
// ConfigFact. The assertion is that fact.Values["WEBHOOK_URL"] == "[secret]",
// proving that looksLikeNetworkAddrList correctly excludes https:// from its
// tcp/unix allowlist, leaving the entropy gate to catch the webhook token.
func TestWebhookURLRedactionParserFed(t *testing.T) {
	path := filepath.Join("testdata", "webhook_redaction.env")
	fact := collectConfigInternal(path, parseDotenv)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false; fixture parse failed — check webhook_redaction.env")
	}

	// WEBHOOK_URL: high-entropy https:// webhook must be redacted by the entropy
	// gate. looksLikeNetworkAddrList must NOT exempt https://, so the full URL
	// (including the high-entropy service token in the path) triggers "[secret]".
	webhookKey := "WEBHOOK_URL"
	if got := fact.Values[webhookKey]; got != "[secret]" {
		t.Errorf("FIX-8: %s = %q, want \"[secret]\" (https:// webhook with high-entropy path must be redacted; looksLikeNetworkAddrList must not exempt https://)",
			webhookKey, got)
	}

	// Plain values must survive verbatim through the pipeline.
	if got := fact.Values["LOG_LEVEL"]; got != "info" {
		t.Errorf("FIX-8: LOG_LEVEL = %q, want \"info\" (plain value must not be masked)", got)
	}
	if got := fact.Values["PORT"]; got != "8080" {
		t.Errorf("FIX-8: PORT = %q, want \"8080\" (plain value must not be masked)", got)
	}
}

// TestLooksLikeNetworkAddrListNarrow asserts that only tcp:// and unix://
// bypass the entropy gate. http://, https://, and udp:// values with high
// entropy must be classified as "secret" so that webhook tokens like
// https://hooks.example.com/services/T00/B00/HighEntropyToken are not leaked.
func TestLooksLikeNetworkAddrListNarrow(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		value      string
		wantClass  string
		wantBypass bool // whether looksLikeNetworkAddrList should return true
	}{
		{
			name:       "tcp docker host passes through",
			key:        "DOCKER_HOST",
			value:      "tcp://0.0.0.0:2375",
			wantClass:  "plain",
			wantBypass: true,
		},
		{
			name:       "unix docker socket passes through",
			key:        "DOCKER_HOST",
			value:      "unix:///var/run/docker.sock",
			wantClass:  "plain",
			wantBypass: true,
		},
		{
			name:       "mixed tcp+unix host list passes through",
			key:        "DOCKER_HOSTS",
			value:      "tcp://0.0.0.0:2375,unix:///var/run/docker.sock",
			wantClass:  "plain",
			wantBypass: true,
		},
		{
			name:       "high-entropy https webhook is redacted",
			key:        "WEBHOOK_URL",
			value:      "https://hooks.example.com/services/xK9mP2nQ7rT4vW8yZ1cB6dF3gH0jL5oMnPqRsTuVwX",
			wantClass:  "secret",
			wantBypass: false,
		},
		{
			name:       "high-entropy http url is redacted",
			key:        "CALLBACK_URL",
			value:      "http://example.com/callback/xK9mP2nQ7rT4vW8yZ1cB6dF3gH0jL5oM",
			wantClass:  "secret",
			wantBypass: false,
		},
		{
			name:       "udp url is not bypassed",
			key:        "SYSLOG_ENDPOINT",
			value:      "udp://logs.example.com/T0AB1CD2EF/B3GH4IJ5KL/MNOPQRSTUVWXYZabcde",
			wantClass:  "secret",
			wantBypass: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBypass := looksLikeNetworkAddrList(tt.value)
			if gotBypass != tt.wantBypass {
				t.Errorf("looksLikeNetworkAddrList(%q) = %v, want %v", tt.value, gotBypass, tt.wantBypass)
			}
			gotClass := classOf(tt.key, tt.value)
			if gotClass != tt.wantClass {
				t.Errorf("classOf(%q, %q) = %q, want %q", tt.key, tt.value, gotClass, tt.wantClass)
			}
		})
	}
}
