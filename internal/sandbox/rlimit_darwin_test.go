//go:build darwin

package sandbox

import "strings"

import "testing"

func TestUlimitPrefix(t *testing.T) {
	pfx := ulimitPrefix(DefaultLimits())

	// DefaultLimits(): CPU=10, NoFile=1024, FSIZE=64<<20.
	// ulimit uses 1024-byte blocks for -f; we assert presence, not exact block
	// math, but the CPU/NOFILE values are direct.
	for _, want := range []string{
		"ulimit -t 10",   // CPU seconds
		"ulimit -n 1024", // NoFile
		"ulimit -f ",     // file size
	} {
		if !strings.Contains(pfx, want) {
			t.Errorf("ulimit prefix missing %q\ngot: %s", want, pfx)
		}
	}

	// RLIMIT_AS is deliberately not applied: -v must be ABSENT so node/V8,
	// Python, and -race binaries are not killed for over-reserving virtual AS.
	if strings.Contains(pfx, "ulimit -v") {
		t.Errorf("ulimit -v (address space) must NOT be set, got: %s", pfx)
	}
	// RLIMIT_NPROC is deliberately not applied: -u is per-uid and starves
	// legitimate multithreaded runtimes, so it must be ABSENT.
	if strings.Contains(pfx, "ulimit -u") {
		t.Errorf("ulimit -u (max user processes) must NOT be set, got: %s", pfx)
	}
	// File size 64 MiB expressed in 1024-byte blocks = 65536.
	if !strings.Contains(pfx, "ulimit -f 65536") {
		t.Errorf("expected FSIZE limit of 65536 blocks, got: %s", pfx)
	}
	// Must end with a separator so it composes with the real command.
	if !strings.HasSuffix(pfx, "; ") {
		t.Errorf("prefix must end with '; ' separator, got: %q", pfx)
	}
}
