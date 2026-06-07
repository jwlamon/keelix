//go:build darwin

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDarwinWrapSpec_BuildsSandboxExecCommand(t *testing.T) {
	in := Spec{
		Command: "node",
		Args:    []string{"server.js", "--stdio"},
		Env:     map[string]string{"FOO": "bar"},
	}
	wrapped, tier, applied := wrapDarwinSpec(in, "/usr/bin/sandbox-exec")

	if tier != "seatbelt" || !applied {
		t.Fatalf("expected tier=seatbelt applied=true, got tier=%q applied=%v", tier, applied)
	}
	if wrapped.Command != "/bin/sh" {
		t.Fatalf("expected /bin/sh wrapper, got %q", wrapped.Command)
	}
	if len(wrapped.Args) != 2 || wrapped.Args[0] != "-c" {
		t.Fatalf("expected [-c <script>], got %v", wrapped.Args)
	}
	script := wrapped.Args[1]
	for _, want := range []string{
		"ulimit -t 10",
		"exec '/usr/bin/sandbox-exec' -p",
		"(deny network*)",
		"'node'",
		"'server.js'",
		"'--stdio'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("wrapped script missing %q\nscript: %s", want, script)
		}
	}
	// Env must be carried through untouched (baseRunner enforces clean env).
	if wrapped.Env["FOO"] != "bar" {
		t.Errorf("env not preserved: %v", wrapped.Env)
	}

	// The profile's writable root must be the RESOLVED system temp root.
	wantRoot, _ := filepath.EvalSymlinks(os.TempDir())
	if !strings.Contains(script, wantRoot) {
		t.Errorf("profile writable root %q not resolved in script: %s", wantRoot, script)
	}
}

func TestDarwinWrapSpec_FallsBackToTier0WhenNoSandboxExec(t *testing.T) {
	in := Spec{Command: "node", Args: []string{"x"}}
	wrapped, tier, applied := wrapDarwinSpec(in, "")

	if tier != "tier0" || applied {
		t.Fatalf("expected tier0 fallback (applied=false), got tier=%q applied=%v", tier, applied)
	}
	// Fallback returns the Spec unchanged for baseRunner to run bare.
	if wrapped.Command != "node" || len(wrapped.Args) != 1 || wrapped.Args[0] != "x" {
		t.Fatalf("fallback must not rewrite the command, got %q %v", wrapped.Command, wrapped.Args)
	}
}

// TestDarwinRunner_StartApplied verifies that Session.Applied() reflects whether
// Seatbelt actually engaged: true when sandbox-exec is available, false when not.
func TestDarwinRunner_StartApplied(t *testing.T) {
	sandboxExecPath := lookupSandboxExec()
	_, _, wantApplied := wrapDarwinSpec(Spec{Command: "/bin/cat"}, sandboxExecPath)

	r := &darwinRunner{}
	sess, err := r.Start(context.Background(), Spec{
		Command: "/bin/cat",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Skipf("darwinRunner.Start unavailable on this host: %v", err)
	}
	defer sess.Close()

	got := sess.Applied()
	if got != wantApplied {
		t.Errorf("Session.Applied() = %v, want %v (wrapDarwinSpec applied=%v, sandbox-exec=%q)",
			got, wantApplied, wantApplied, sandboxExecPath)
	}
}

// TestDarwinRunner_StartTierNotTier0 verifies that Session.Tier() returns the
// real sandbox tier (not the hardcoded "tier0") when darwinRunner.Start is used.
// This covers the bug where wrapDarwinSpec's tier return value was discarded.
// When sandbox-exec is unavailable the expected tier is "tier0" (fallback), which
// is still a valid and honest answer — the test only guards against the session
// lying when Seatbelt is actually applied.
func TestDarwinRunner_StartTierNotTier0(t *testing.T) {
	sandboxExecPath := lookupSandboxExec()
	_, expectedTier, _ := wrapDarwinSpec(Spec{Command: "/bin/cat"}, sandboxExecPath)

	r := &darwinRunner{}
	sess, err := r.Start(context.Background(), Spec{
		Command: "/bin/cat",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Skipf("darwinRunner.Start unavailable on this host: %v", err)
	}
	defer sess.Close()

	got := sess.Tier()
	if got != expectedTier {
		t.Errorf("Session.Tier() = %q, want %q (tier was not propagated from wrapDarwinSpec)", got, expectedTier)
	}
	// Extra guard: if sandbox-exec is present, tier must NOT be "tier0".
	if sandboxExecPath != "" && got == "tier0" {
		t.Errorf("Session.Tier() = %q (hardcoded tier0 leaked through) but sandbox-exec is available at %s", got, sandboxExecPath)
	}
}
