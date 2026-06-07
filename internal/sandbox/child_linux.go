//go:build linux

package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// netConfinedMarkerPrefix is the prefix for the net-confined marker line the
// child writes to stderr on the line immediately after the applied marker.
// The parent (runner_linux.go) parses this to surface the network-isolation
// guarantee honestly: Landlock ABI <4 (kernel <6.7) strips net rights under
// BestEffort and returns nil without denying any TCP, so without this marker
// the parent would silently claim full isolation.
const netConfinedMarkerPrefix = "keelix-sandbox: net-confined="

// kernelLandlockABI returns the Landlock ABI version the running kernel supports
// (0 = no Landlock at all). Network-deny requires ABI >= 4 (kernel 6.7).
func kernelLandlockABI() int {
	v, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		return 0
	}
	return v
}

// landlockStrictSupported reports whether STRICT (non-BestEffort) Landlock V1
// can be enforced on this kernel, by attempting an enforcement that only allows
// the given probe dir RW. Because Landlock is per-thread-sticky, we only call
// this from a throwaway probe path (tests); the real child uses applyLandlock.
func landlockStrictSupported(probeDir string) bool {
	return landlock.V1.RestrictPaths(landlock.RWDirs(probeDir)) == nil
}

// resolveCommand turns the command the trampoline is about to exec into an
// absolute, symlink-resolved path so its containing directory can be added to
// the Landlock allowlist with READ+EXECUTE. Without this the kernel denies the
// exec of any interpreter that lives outside the static system allowlist —
// e.g. an nvm/fnm node under ~/.nvm/.../bin/node, a uv/pipx tool, or a
// project-local binary (and, in tests, the test binary under /tmp/go-build...).
//
// Resolution mirrors exec.LookPath/syscall.Exec semantics:
//   - no '/' in cmd  => search the child's PATH via exec.LookPath.
//   - otherwise      => filepath.Abs relative to the child's cwd.
//
// filepath.EvalSymlinks is then applied best-effort so a symlinked interpreter
// (the common case for nvm/homebrew shims) resolves to the real on-disk binary
// whose directory we allow. On any resolution error the original cmd is
// returned unchanged and the caller still attempts the exec — Landlock will
// simply deny it as before, never widening access.
func resolveCommand(cmd string) string {
	var abs string
	if strings.ContainsRune(cmd, '/') {
		a, err := filepath.Abs(cmd)
		if err != nil {
			return cmd
		}
		abs = a
	} else {
		p, err := exec.LookPath(cmd)
		if err != nil {
			return cmd
		}
		abs = p
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	return abs
}

// applyLandlock enforces the filesystem + network policy for the sandboxed
// child: read-only system dirs + the npm/uvx caches passed in roCaches, RW only
// the tempdir, and (kernel >=6.7) deny ALL outbound/inbound TCP. $HOME is
// DELIBERATELY excluded from RODirs so a poisoned MCP server cannot read
// ~/.ssh, ~/.aws, or agent tokens.
//
// cmdDir is the directory of the resolved command the trampoline is about to
// exec (see resolveCommand). It is added READ+EXECUTE so the kernel permits the
// exec of interpreters living outside the static system allowlist (user-local
// node/uv/pipx, project-local binaries, the test binary under /tmp/go-build...).
// RODirs grants execute on contained files (accessFSRead includes
// LANDLOCK_ACCESS_FS_EXECUTE in go-landlock v0.8.1), and we allow the whole
// directory rather than the single file because interpreters frequently need
// adjacent files (shared objects, wrapper scripts) at exec time. Only this one
// resolved command dir becomes readable — $HOME stays denied, never widened.
func applyLandlock(tempDir string, roCaches []string, homeDir, cmdDir string) (applied bool, netConfined bool, err error) {
	roDirs := []string{"/usr", "/bin", "/lib", "/lib64", "/etc"}
	roDirs = append(roDirs, roCaches...)
	if cmdDir != "" {
		roDirs = append(roDirs, cmdDir)
	}

	// IgnoreIfMissing: /lib64, the caches, and cmdDir may not exist on every
	// distro/box (cmdDir is resolved best-effort and could be stale).
	rules := []landlock.Rule{
		landlock.RODirs(roDirs...).IgnoreIfMissing(),
		landlock.RWDirs(tempDir),
	}
	if err = landlock.V5.BestEffort().RestrictPaths(rules...); err != nil {
		return false, false, err
	}
	// Deny all TCP connect/bind (no NetRules => everything denied). Requires
	// Landlock ABI v4 (kernel 6.7); BestEffort no-ops it on older kernels.
	if err = landlock.V5.BestEffort().RestrictNet(); err != nil {
		return false, false, err
	}

	// Detect whether RestrictNet() above actually enforced network denial.
	// BestEffort strips net rights on kernels that don't support them (ABI < 4)
	// and returns nil — the call APPEARS to succeed but no network confinement
	// was applied. We check the kernel ABI directly to be honest.
	netConfined = kernelLandlockABI() >= 4

	// Honest degradation check: if even STRICT V1 fails, BestEffort above was a
	// no-op and nothing is actually enforced. We can't re-probe with the live
	// tempdir (already restricted), so probe a fresh throwaway dir.
	probe, mkErr := os.MkdirTemp("", "keelix-ll-probe-")
	if mkErr != nil {
		// Can't probe; assume applied since the BestEffort calls returned nil.
		return true, netConfined, nil
	}
	defer os.RemoveAll(probe)
	applied = landlockStrictSupported(probe)
	return applied, netConfined, nil
}

// sandboxAppliedMarker returns the single line the trampoline child writes to
// its real stderr so the parent can verify whether isolation actually applied.
// It reuses markerLinePrefix from base.go (accessible on linux via the shared
// build tag) so the producer and parser are guaranteed to match.
func sandboxAppliedMarker(applied bool) string {
	return fmt.Sprintf("%s%t", markerLinePrefix, applied)
}

// sandboxNetConfinedMarker returns the net-confined marker line the trampoline
// child writes to stderr immediately after the applied marker. The parent
// (runner_linux.go) parses it to surface the network-isolation guarantee.
func sandboxNetConfinedMarker(netConfined bool) string {
	return fmt.Sprintf("%s%t", netConfinedMarkerPrefix, netConfined)
}

// parseAppliedMarker scans captured child stderr for the applied marker.
// Absent or applied=false => not honestly isolated. Used by Run() which
// captures the full stderr buffer; the Start() path uses parseAppliedMarkerLine
// on the first stderr line via the appliedCh goroutine.
func parseAppliedMarker(stderr []byte) bool {
	for _, line := range bytes.Split(stderr, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == markerLinePrefix+"true" {
			return true
		}
	}
	return false
}

// parseNetConfinedMarker scans captured child stderr for the net-confined marker.
// Returns false when absent (safe default: assume not confined). Used by Run()
// in runner_linux.go to populate Result.Notes honestly.
func parseNetConfinedMarker(stderr []byte) bool {
	for _, line := range bytes.Split(stderr, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == netConfinedMarkerPrefix+"true" {
			return true
		}
		if s == netConfinedMarkerPrefix+"false" {
			return false
		}
	}
	return false
}

// RunSandboxChild is the entrypoint of the hidden `keelix __mcp-sandbox-child`
// command. argv layout produced by the parent (runner_linux.go) is:
//
//	args = [<tempDir> <homeDir> <cacheCSV> "--" <realCmd> <realArgs...>]
//
// It self-restricts (rlimits + NO_NEW_PRIVS + Landlock), prints the applied
// marker to stderr, then syscall.Exec's the real command IN PLACE. Returns a
// process exit code; it only returns on a setup error (exec replaces us).
func RunSandboxChild(args []string) int {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 3 || sep+1 >= len(args) {
		fmt.Fprintln(os.Stderr, "keelix-sandbox: malformed child argv")
		return 2
	}
	tempDir := args[0]
	homeDir := args[1]
	var caches []string
	if csv := args[2]; csv != "" {
		caches = strings.Split(csv, string(os.PathListSeparator))
	}
	cmd := args[sep+1]
	cmdArgs := args[sep+1:] // argv0 included for exec

	// Resolve the command to the real on-disk binary BEFORE restricting, so its
	// directory can be allowed read+execute in Landlock — otherwise the kernel
	// denies the exec of any interpreter outside the static system allowlist.
	// resolveCommand uses the child's (already-cleaned) PATH for bare names and
	// resolves symlinks; on failure it returns cmd unchanged.
	resolved := resolveCommand(cmd)
	cmdDir := ""
	if filepath.IsAbs(resolved) {
		cmdDir = filepath.Dir(resolved)
	}

	if err := applyChildLimits(DefaultLimits()); err != nil {
		fmt.Fprintln(os.Stderr, "keelix-sandbox: limits:", err)
		return 2
	}
	applied, netConfined, err := applyLandlock(tempDir, caches, homeDir, cmdDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keelix-sandbox: landlock:", err)
		// landlock setup error is non-fatal to the probe; report not-applied.
		applied = false
		netConfined = false
	}
	// Two honest marker lines the parent parses for Result.SandboxApplied and
	// net-confined status. net-confined=false on kernels 5.13-6.6 means the
	// BestEffort RestrictNet() call was silently stripped — TCP is NOT denied.
	fmt.Fprintln(os.Stderr, sandboxAppliedMarker(applied))
	fmt.Fprintln(os.Stderr, sandboxNetConfinedMarker(netConfined))

	// Exec the path we resolved above (already allowlisted). If resolution
	// failed it may be a bare name; fall back to LookPath under the post-restrict
	// PATH so the error path stays identical to before.
	if !filepath.IsAbs(resolved) {
		p, lerr := exec.LookPath(cmd)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "keelix-sandbox: lookpath:", lerr)
			return 127
		}
		resolved = p
	}
	if err := syscall.Exec(resolved, cmdArgs, os.Environ()); err != nil { // #nosec G204 -- the sandbox's purpose is to exec this command under Landlock/rlimit confinement; consent-gated and off by default
		fmt.Fprintln(os.Stderr, "keelix-sandbox: exec:", err)
		return 126
	}
	return 0 // unreachable on success
}

// applyChildLimits self-applies the no-exec portion of the trampoline:
// PR_SET_NO_NEW_PRIVS (so the sandbox can never be escalated away across the
// upcoming exec) followed by the resource rlimits from limits.go. It is split
// out from RunSandboxChild so it can be unit-tested without spawning a process.
func applyChildLimits(lim Limits) error {
	// PR_SET_NO_NEW_PRIVS=1: the exec'd command and all its children can never
	// gain privileges via setuid/setgid/file caps.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return errno
	}
	set := func(res int, n uint64) error {
		rl := unix.Rlimit{Cur: n, Max: n}
		return unix.Setrlimit(res, &rl)
	}
	if err := set(unix.RLIMIT_CPU, uint64(lim.CPUSeconds)); err != nil {
		return err
	}
	// RLIMIT_AS and RLIMIT_NPROC are intentionally not set: RLIMIT_AS caps
	// virtual address space and RLIMIT_NPROC is per-uid; both kill legitimate
	// multithreaded runtimes (node/V8, Python, -race). Timeout + RLIMIT_CPU +
	// process-group kill + output cap bound resource use instead (see limits.go).
	if err := set(unix.RLIMIT_NOFILE, uint64(lim.NoFile)); err != nil {
		return err
	}
	if err := set(unix.RLIMIT_FSIZE, uint64(lim.FileSizeBytes)); err != nil {
		return err
	}
	return nil
}
