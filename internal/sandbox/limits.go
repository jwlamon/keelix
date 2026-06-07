package sandbox

// Limits are the per-process resource ceilings applied to a sandboxed child.
// The Tier-0 baseRunner records them but does not enforce them (it has no
// kernel hook); the linux and darwin runners apply them via setrlimit/Prlimit.
// Centralizing them here keeps the values identical across tiers.
//
// RLIMIT_AS and RLIMIT_NPROC are deliberately NOT set:
//
//   - RLIMIT_AS caps virtual address space, which node/V8, Python, and -race
//     (ThreadSanitizer) binaries over-reserve by tens of GiB even though their
//     resident memory stays small; a tight RLIMIT_AS would kill legitimate MCP
//     servers (and the -race test binaries).
//
//   - RLIMIT_NPROC is PER-UID, not per-process: it counts every process and
//     thread already owned by the real uid, so on a busy CI runner the build
//     user has burned most of the budget before the child even starts. A low
//     value also starves legitimate multithreaded runtimes (the Go runtime +
//     ThreadSanitizer, node/libuv/V8, Python) which each spawn dozens of
//     threads, making pthread_create fail with EAGAIN ("Resource temporarily
//     unavailable"). It is the wrong tool for bounding a single short-lived
//     child.
//
// Resource abuse is bounded instead by the wall-clock timeout, the
// process-group kill, RLIMIT_CPU (runaway CPU / fork bombs), RLIMIT_FSIZE
// (disk writes), and the output cap. The Landlock deny-$HOME / deny-network
// guarantees are independent of any of these rlimits.
type Limits struct {
	CPUSeconds    uint64 // RLIMIT_CPU, seconds of CPU time
	NoFile        uint64 // RLIMIT_NOFILE, max open file descriptors
	FileSizeBytes uint64 // RLIMIT_FSIZE, max size of any file the child writes
}

// DefaultLimits returns the conservative ceilings used for MCP probe children:
// an MCP server only has to answer initialize + tools/list, so it needs very
// little CPU time or disk-write headroom. Memory and process/thread count are
// bounded by the timeout + RLIMIT_CPU + process-group kill + output cap, not
// by RLIMIT_AS or RLIMIT_NPROC (see the Limits doc comment). NoFile is 1024 — a
// sane default; node/libuv/V8 routinely opens hundreds of fds, so a tighter cap
// (e.g. 64) starves them.
func DefaultLimits() Limits {
	return Limits{
		CPUSeconds:    10,
		NoFile:        1024,
		FileSizeBytes: 64 << 20, // 64 MiB
	}
}
