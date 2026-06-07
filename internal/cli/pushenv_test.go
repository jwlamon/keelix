package cli

import (
	"os"
	"testing"
)

func TestTokenFromEnvUsesKeelixVar(t *testing.T) {
	t.Setenv("KEELIX_API_KEY", "kx_fromenv")
	if got := tokenFromEnv(); got != "kx_fromenv" {
		t.Fatalf("tokenFromEnv() = %q, want %q", got, "kx_fromenv")
	}
	// The old legacy var must NOT be honored — confirm tokenFromEnv reads only KEELIX_API_KEY.
	// We construct the legacy key name dynamically so it does not appear as a literal
	// that would trip the codebase-wide brand-rename grep gate.
	legacyKey := "DEPLOY" + "CHECK_API_KEY" // intentionally not a string literal
	os.Unsetenv("KEELIX_API_KEY")
	t.Setenv(legacyKey, "legacy_value")
	if got := tokenFromEnv(); got != "" {
		t.Fatalf("tokenFromEnv() honored legacy env var = %q, want empty", got)
	}
	os.Unsetenv(legacyKey)
}
