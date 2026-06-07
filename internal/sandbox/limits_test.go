package sandbox

import "testing"

// TestDefaultLimits pins the conservative defaults SLB/SLC apply via setrlimit.
func TestDefaultLimits(t *testing.T) {
	l := DefaultLimits()
	if l.CPUSeconds != 10 {
		t.Errorf("CPUSeconds = %d, want 10", l.CPUSeconds)
	}
	// RLIMIT_AS and RLIMIT_NPROC are deliberately not enforced (RLIMIT_AS caps
	// virtual address space and RLIMIT_NPROC is per-uid; both break node/V8,
	// Python, and -race runtimes). There is no AddressSpaceBytes or NProc field
	// to assert. See limits.go.
	if l.NoFile != 1024 {
		t.Errorf("NoFile = %d, want 1024", l.NoFile)
	}
	if l.FileSizeBytes != 64<<20 {
		t.Errorf("FileSizeBytes = %d, want %d", l.FileSizeBytes, 64<<20)
	}
}
