//go:build linux

package sandbox

import "testing"

// TestAvailableLinux asserts that Available() on linux agrees with
// kernelLandlockABI() > 0. Both probe the same kernel capability.
// This is a REAL non-skipped test — reading the Landlock ABI version is a
// non-privileged syscall (landlock_get_abi_version(2)).
func TestAvailableLinux(t *testing.T) {
	got := Available()
	abi := kernelLandlockABI()
	want := abi > 0
	if got != want {
		t.Errorf("Available() = %v but kernelLandlockABI()=%d (>0 = %v); they must agree",
			got, abi, want)
	}
}
