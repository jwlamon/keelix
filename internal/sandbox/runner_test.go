package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestNewRunnerSmoke asserts NewRunner returns a usable Runner on whatever
// platform the test runs on (Tier-0 fallback at minimum).
func TestNewRunnerSmoke(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
	res, err := r.Run(context.Background(), Spec{
		Command: "/bin/sh",
		Args:    []string{"-c", `printf hello`},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "hello" {
		t.Errorf("stdout = %q, want hello", got)
	}
	if res.Tier == "" {
		t.Error("Result.Tier is empty, want a tier label")
	}
}
