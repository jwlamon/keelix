//go:build darwin

package sandbox

import "fmt"

// ulimitPrefix renders a POSIX-sh `ulimit ...; ` prefix applying the given
// Limits to the child and its grandchildren. macOS has no per-pid Prlimit
// (golang.org/x/sys/unix exposes only the current-process Setrlimit on
// darwin), so we apply rlimits the portable way: a ulimit prefix executed by
// /bin/sh just before exec'ing the sandboxed command. This is darwin-correct
// and inherits across the sandbox-exec boundary.
//
// ulimit unit quirks: -f (file size) is in 1024-byte blocks; -t (CPU) is
// seconds; -n (open files) is a count.
//
// -v (virtual address space) and -u (max user processes) are intentionally NOT
// applied: -v caps virtual address space and -u is per-uid; both kill
// legitimate multithreaded runtimes (node/V8, Python, -race) that over-reserve
// AS or spawn dozens of threads. The wall-clock timeout + -t CPU cap +
// process-group kill + output cap bound resource use instead (see limits.go).
func ulimitPrefix(l Limits) string {
	fsizeBlocks := l.FileSizeBytes / 1024
	return fmt.Sprintf(
		"ulimit -t %d; ulimit -n %d; ulimit -f %d; ",
		l.CPUSeconds, l.NoFile, fsizeBlocks,
	)
}
