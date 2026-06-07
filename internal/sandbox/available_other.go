//go:build !linux && !darwin

package sandbox

// Available reports whether a real kernel-level sandbox tier (above Tier-0
// process hygiene) is usable on this host. On platforms other than linux and
// darwin no isolation backend is available, so this always returns false.
func Available() bool {
	return false
}
