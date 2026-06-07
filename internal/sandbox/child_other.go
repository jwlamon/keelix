//go:build !linux

package sandbox

// RunSandboxChild is only meaningful on linux (the re-exec trampoline). On
// other platforms the hidden cobra command exists for symmetry but does
// nothing; the darwin/other runners never invoke it.
func RunSandboxChild(args []string) int { return 0 }
