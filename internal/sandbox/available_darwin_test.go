//go:build darwin

package sandbox

import "testing"

// TestAvailableDarwin asserts that Available() on darwin agrees with
// lookupSandboxExec(): both probe the same capability (sandbox-exec on PATH).
// This is a REAL non-skipped test — sandbox-exec is part of macOS and does
// not require elevated privileges.
func TestAvailableDarwin(t *testing.T) {
	got := Available()
	wantFromPath := lookupSandboxExec() != ""
	if got != wantFromPath {
		t.Errorf("Available() = %v but lookupSandboxExec()=%q (present=%v); they must agree",
			got, lookupSandboxExec(), wantFromPath)
	}
}
