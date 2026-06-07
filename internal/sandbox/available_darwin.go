//go:build darwin

package sandbox

// Available reports whether a real kernel-level sandbox tier (above Tier-0
// process hygiene) is usable on this host. On darwin that means Seatbelt
// (sandbox-exec) is present on PATH; the darwinRunner falls back to Tier-0
// when it is absent.
func Available() bool {
	return lookupSandboxExec() != ""
}
