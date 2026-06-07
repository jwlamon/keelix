//go:build !linux

package sandbox

// runLandlockProbe is Linux-only (Landlock). On other platforms the trampoline
// is never exec'd with __landlock-probe, so this stub only exists to satisfy
// the platform-neutral TestMain reference. It should never be called.
func runLandlockProbe(_ []string) int { return 0 }
