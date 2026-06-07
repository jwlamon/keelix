package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestResolveMCPConsent_NotEnabled(t *testing.T) {
	var out bytes.Buffer
	ok := resolveMCPConsent(consentEnv{
		enabled:   false,
		consented: false,
		isTTY:     true,
		commands:  []string{"npx foo"},
	}, strings.NewReader(""), &out)
	if !ok {
		t.Fatal("disabled probe must report ok (nothing to gate)")
	}
}

func TestResolveMCPConsent_AlreadyConsented(t *testing.T) {
	var out bytes.Buffer
	ok := resolveMCPConsent(consentEnv{
		enabled:   true,
		consented: true,
		isTTY:     false,
		commands:  []string{"npx foo"},
	}, strings.NewReader(""), &out)
	if !ok {
		t.Fatal("pre-consented probe must proceed")
	}
}

func TestResolveMCPConsent_NonTTYRefuses(t *testing.T) {
	var out bytes.Buffer
	ok := resolveMCPConsent(consentEnv{
		enabled:   true,
		consented: false,
		isTTY:     false,
		commands:  []string{"npx evil"},
	}, strings.NewReader("y\n"), &out)
	if ok {
		t.Fatal("non-TTY without --probe-mcp-yes must REFUSE (no probe)")
	}
	if !strings.Contains(out.String(), "refusing") {
		t.Errorf("expected refusal notice, got %q", out.String())
	}
}

func TestResolveMCPConsent_TTYYesProceeds(t *testing.T) {
	var out bytes.Buffer
	ok := resolveMCPConsent(consentEnv{
		enabled:   true,
		consented: false,
		isTTY:     true,
		commands:  []string{"npx server-a", "uvx server-b"},
	}, strings.NewReader("y\n"), &out)
	if !ok {
		t.Fatal("TTY + 'y' must proceed")
	}
	// The exact commands that will execute must be shown before the prompt.
	if !strings.Contains(out.String(), "npx server-a") || !strings.Contains(out.String(), "uvx server-b") {
		t.Errorf("prompt must show the exact commands, got %q", out.String())
	}
}

func TestResolveMCPConsent_TTYNoRefuses(t *testing.T) {
	var out bytes.Buffer
	ok := resolveMCPConsent(consentEnv{
		enabled:   true,
		consented: false,
		isTTY:     true,
		commands:  []string{"npx server-a"},
	}, strings.NewReader("\n"), &out)
	if ok {
		t.Fatal("TTY + default (empty) answer must NOT proceed (y/N defaults to No)")
	}
}
