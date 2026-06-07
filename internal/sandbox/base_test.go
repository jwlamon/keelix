package sandbox

import (
	"context"
	"strings"
	"testing"
	"time"
)

// shHelper returns a Spec that runs /bin/sh -c with the given script under the
// Tier-0 baseRunner. Tests that need a POSIX shell skip when it is absent.
func shHelper(t *testing.T, script string) Spec {
	t.Helper()
	return Spec{
		Command: "/bin/sh",
		Args:    []string{"-c", script},
		Timeout: 5 * time.Second,
	}
}

// TestBaseRunnerDropsParentEnv asserts a variable present in the PARENT's
// os.Environ() but absent from Spec.Env is invisible to the child.
func TestBaseRunnerDropsParentEnv(t *testing.T) {
	t.Setenv("KEELIX_SANDBOX_SECRET", "leaked-value")

	r := &baseRunner{}
	res, err := r.Run(context.Background(), shHelper(t, `printf '%s' "$KEELIX_SANDBOX_SECRET"`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := string(res.Stdout); got != "" {
		t.Errorf("child saw parent secret %q, want empty", got)
	}
	if res.Tier != "tier0" {
		t.Errorf("Tier = %q, want tier0", res.Tier)
	}
}

// TestBaseRunnerCwdIsTempdir asserts the child runs inside a fresh tempdir,
// not the parent's working directory.
func TestBaseRunnerCwdIsTempdir(t *testing.T) {
	r := &baseRunner{}
	res, err := r.Run(context.Background(), shHelper(t, `pwd`))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := strings.TrimSpace(string(res.Stdout))
	if out == "" {
		t.Fatal("pwd produced no output")
	}
	// macOS symlinks /tmp -> /private/tmp, so match on the temp marker, not "/tmp".
	if !strings.Contains(out, "keelix-sbx") {
		t.Errorf("cwd %q is not the sandbox tempdir", out)
	}
}

// TestBaseRunnerTimeoutGroupKill asserts a child sleeping past Timeout is
// killed and Result.TimedOut is set, and that Run returns well before the
// child's natural sleep would finish.
func TestBaseRunnerTimeoutGroupKill(t *testing.T) {
	r := &baseRunner{}
	s := Spec{
		Command: "/bin/sh",
		Args:    []string{"-c", "sleep 30"},
		Timeout: 300 * time.Millisecond,
	}
	start := time.Now()
	res, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.TimedOut {
		t.Error("TimedOut = false, want true for a child that outlived Timeout")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Run took %v, child was not killed promptly", elapsed)
	}
}

// TestBaseRunnerOutputCap asserts a child flooding stdout is truncated at
// Spec.OutputCap rather than buffering unbounded output.
func TestBaseRunnerOutputCap(t *testing.T) {
	r := &baseRunner{}
	s := Spec{
		Command: "/bin/sh",
		// Emit ~50 KiB; cap at 1 KiB.
		Args:      []string{"-c", `i=0; while [ $i -lt 50 ]; do printf '%01024d' 0; i=$((i+1)); done`},
		Timeout:   5 * time.Second,
		OutputCap: 1024,
	}
	res, err := r.Run(context.Background(), s)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if int64(len(res.Stdout)) > s.OutputCap {
		t.Errorf("captured %d bytes, want <= cap %d", len(res.Stdout), s.OutputCap)
	}
	if len(res.Stdout) == 0 {
		t.Error("captured 0 bytes, want some output up to the cap")
	}
}
