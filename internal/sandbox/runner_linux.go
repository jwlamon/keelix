//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// linuxRunner adds the Tier-1 re-exec trampoline + Landlock on top of the
// portable baseRunner. It embeds baseRunner so Tier-0 guarantees (clean env,
// tempdir cwd, pgid group-kill, output cap) are inherited unchanged.
type linuxRunner struct {
	baseRunner
}

// newPlatformRunner is selected by NewRunner() on linux (build-tagged).
func newPlatformRunner() Runner { return &linuxRunner{} }

// selfExe resolves the path of the currently-running keelix binary, which we
// re-exec as the __mcp-sandbox-child trampoline.
func selfExe() (string, error) { return os.Executable() }

// wrapChild rewrites a real command into the trampoline argv:
//
//	<self> __mcp-sandbox-child <tempDir> <homeDir> <cacheCSV> -- <cmd> <args...>
func wrapChild(self, tempDir, homeDir string, caches []string, cmd string, args []string) (string, []string) {
	csv := strings.Join(caches, string(os.PathListSeparator))
	out := []string{"__mcp-sandbox-child", tempDir, homeDir, csv, "--"}
	out = append(out, cmd)
	out = append(out, args...)
	return self, out
}

// selectTier returns the isolation tier label for the current host. The runner
// always uses the Landlock trampoline; bwrap / nsjail are never exec'd, so
// "bwrap" is not a valid return value. The bwrapPath and usernsRestricted
// parameters are retained for signature compatibility with tests but are
// intentionally unused — the tier is always "landlock". SBX-9(c).
func selectTier(_ string, _ bool) string {
	return "landlock"
}

// usernsRestricted reads kernel.apparmor_restrict_unprivileged_userns (==1
// means unprivileged userns is blocked). Absent/0 => not restricted.
func usernsRestricted() bool {
	b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

// detectBwrap returns the bwrap (or nsjail) path if a usable one is on PATH.
func detectBwrap() string {
	for _, name := range []string{"bwrap", "nsjail"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// applyPrlimit belt-and-suspenders the rlimits onto an already-started child
// pid, closing the Tier-0 Start()->limits race window.
func applyPrlimit(pid int, lim Limits) {
	set := func(res int, n uint64) {
		rl := unix.Rlimit{Cur: n, Max: n}
		_ = unix.Prlimit(pid, res, &rl, nil)
	}
	set(unix.RLIMIT_CPU, uint64(lim.CPUSeconds))
	// RLIMIT_AS and RLIMIT_NPROC intentionally omitted (see limits.go):
	// virtual-AS cap and per-uid process cap both break node/V8, Python, and
	// -race runtimes.
	set(unix.RLIMIT_NOFILE, uint64(lim.NoFile))
	set(unix.RLIMIT_FSIZE, uint64(lim.FileSizeBytes))
}

// homeDir returns the user's home (denied by Landlock) so the child knows what
// to exclude; falls back to a non-existent path if HOME is unset.
func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/nonexistent"
}

// knownCacheRoots returns the set of directory prefixes that are considered
// safe to allow as read-only Landlock entries. Only paths that are exactly
// equal to, or strict subdirectories of, one of these roots are accepted.
// This prevents cache-path injection (SBX-4): a config env that points
// npm_config_cache at ~/.ssh would otherwise re-grant HOME read access.
//
// The roots are derived from $HOME at call time. On error we fall back to
// a non-existent path that will never match, keeping the default-deny posture.
func knownCacheRoots() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/nonexistent-no-home"
	}
	return []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".cache"),
		filepath.Join(home, "Library", "Caches"), // macOS cross-compile compat
		"/tmp",
	}
}

// allowedCachePath reports whether p is a safe cache path: it must resolve to
// exactly one of the known cache roots or a subdirectory thereof.
//
// Resolution: filepath.Clean is applied (EvalSymlinks is intentionally skipped
// here because the paths may not exist yet; symlink-loop attacks are prevented
// by the prefix check against absolute known roots).
func allowedCachePath(p string) bool {
	if p == "" {
		return false
	}
	p = filepath.Clean(p)
	for _, root := range knownCacheRoots() {
		root = filepath.Clean(root)
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// roCaches collects npm/uvx cache dirs Landlock must allow read-only so server
// launchers can resolve their packages. Each candidate path is validated
// against the known-safe cache roots (SBX-4): any path outside ~/.npm,
// ~/.cache, ~/Library/Caches, or /tmp is silently dropped so a poisoned
// config env like npm_config_cache=~/.ssh cannot re-grant HOME read access.
func roCaches(env map[string]string) []string {
	var out []string
	add := func(p string) {
		if p != "" && allowedCachePath(p) {
			out = append(out, p)
		}
	}
	add(env["npm_config_cache"])
	add(env["UV_CACHE_DIR"])
	add(env["NPM_CONFIG_CACHE"])
	return out
}

// rewrite produces a trampoline Spec from a real Spec: same env/timeout/cap,
// but Command/Args point at the self binary's __mcp-sandbox-child entrypoint.
func (r *linuxRunner) rewrite(s Spec, tempDir string) (Spec, error) {
	self, err := selfExe()
	if err != nil {
		return Spec{}, err
	}
	cmd, args := wrapChild(self, tempDir, homeDir(), roCaches(s.Env), s.Command, s.Args)
	out := s
	out.Command = cmd
	out.Args = args
	return out, nil
}

// Run executes a one-shot sandboxed command via the trampoline.
func (r *linuxRunner) Run(ctx context.Context, s Spec) (*Result, error) {
	tier := selectTier(detectBwrap(), usernsRestricted())
	ws, err := r.baseRunner.workDir()
	if err != nil {
		return nil, err
	}
	defer r.baseRunner.cleanup(ws)

	tramp, err := r.rewrite(s, ws)
	if err != nil {
		return nil, err
	}
	res, pid, err := r.baseRunner.runIn(ctx, tramp, ws)
	if err != nil {
		return nil, err
	}
	if pid > 0 {
		applyPrlimit(pid, DefaultLimits())
	}
	res.Tier = tier
	res.SandboxApplied = parseAppliedMarker(res.Stderr)
	netConfined := parseNetConfinedMarker(res.Stderr)
	if netConfined {
		res.Notes = append(res.Notes, "net-confined=true")
	} else {
		res.Notes = append(res.Notes, "net-confined=false (Landlock ABI <4; kernel <6.7; TCP NOT denied)")
	}
	res.Notes = append(res.Notes, "linux trampoline tier="+tier)
	return res, nil
}

// Start opens a streaming sandboxed session (used by stdio MCP). It wraps the
// command identically and delegates session plumbing to baseRunner.
func (r *linuxRunner) Start(ctx context.Context, s Spec) (Session, error) {
	tier := selectTier(detectBwrap(), usernsRestricted())
	ws, err := r.baseRunner.workDir()
	if err != nil {
		return nil, err
	}
	tramp, err := r.rewrite(s, ws)
	if err != nil {
		r.baseRunner.cleanup(ws)
		return nil, err
	}
	sess, pid, err := r.baseRunner.startIn(ctx, tramp, ws)
	if err != nil {
		r.baseRunner.cleanup(ws)
		return nil, err
	}
	if pid > 0 {
		applyPrlimit(pid, DefaultLimits())
	}
	// Overwrite the hardcoded "tier0" that baseRunner.startIn stores; the
	// linux runner has already selected the real isolation tier above.
	sess.(*baseSession).tier = tier
	return sess, nil
}

// NewRunner returns the strongest sandbox Runner the host supports. On linux
// the linuxRunner wraps baseRunner with the Landlock re-exec trampoline + Prlimit.
func NewRunner() Runner {
	return newPlatformRunner()
}
