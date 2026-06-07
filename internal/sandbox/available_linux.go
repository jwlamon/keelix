//go:build linux

package sandbox

// Available reports whether a real kernel-level sandbox tier (above Tier-0
// process hygiene) is usable on this host. On linux Landlock is used; it
// requires kernel 5.13+. kernelLandlockABI() returns 0 when the kernel does
// not support Landlock at all (pre-5.13 or disabled), so Available() returns
// false in that case, causing the engine to skip the active probe unless
// --probe-mcp-unsandboxed is set.
func Available() bool {
	return kernelLandlockABI() > 0
}
