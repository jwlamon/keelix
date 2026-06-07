//go:build linux

package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelfExe_Resolves(t *testing.T) {
	p, err := selfExe()
	if err != nil {
		t.Fatalf("selfExe: %v", err)
	}
	if p == "" {
		t.Fatalf("selfExe returned empty path")
	}
}

func TestWrapChild_BuildsTrampolineArgv(t *testing.T) {
	tempDir := "/tmp/keelix-xyz"
	home := "/home/u"
	caches := []string{"/c1", "/c2"}
	// Standard exec.Command convention: cmd is the executable, args are the
	// extra arguments — args[0] must NOT duplicate cmd.
	cmd, args := wrapChild("self", tempDir, home, caches, "node", []string{"server.js"})

	if cmd != "self" {
		t.Fatalf("cmd=%q want self", cmd)
	}
	// Expected tail after '--': node server.js
	if args[0] != "__mcp-sandbox-child" {
		t.Fatalf("args[0]=%q", args[0])
	}
	if args[1] != tempDir || args[2] != home {
		t.Fatalf("tempDir/home not threaded: %v", args[:3])
	}
	if !strings.Contains(args[3], "c1") || !strings.Contains(args[3], "c2") {
		t.Fatalf("cacheCSV missing caches: %q", args[3])
	}
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep == -1 {
		t.Fatalf("missing '--' separator in %v", args)
	}
	// After '--': [node server.js]
	tail := args[sep+1:]
	if len(tail) != 2 || tail[0] != "node" || tail[1] != "server.js" {
		t.Fatalf("expected -- node server.js tail, got %v", tail)
	}
}

// TestWrapChild_NoArgs verifies that a command with no extra arguments still
// produces the correct trampoline tail (just the command, no extra entries).
func TestWrapChild_NoArgs(t *testing.T) {
	_, args := wrapChild("self", "/tmp/t", "/home/u", nil, "mybin", nil)
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep == -1 {
		t.Fatalf("missing '--' in %v", args)
	}
	tail := args[sep+1:]
	if len(tail) != 1 || tail[0] != "mybin" {
		t.Fatalf("expected -- mybin, got %v", tail)
	}
}

// TestLinuxRunner_StartTierNotTier0 verifies that Session.Tier() returns the
// real sandbox tier (not the hardcoded "tier0") when linuxRunner.Start is used.
// Requires the self binary to expose __mcp-sandbox-child; skips gracefully when
// running outside the full binary environment (e.g. plain `go test`).
func TestLinuxRunner_StartTierNotTier0(t *testing.T) {
	self, err := selfExe()
	if err != nil {
		t.Skipf("selfExe: %v", err)
	}
	// The test binary is not the keelix CLI, so __mcp-sandbox-child won't work.
	// We test tier propagation by confirming selectTier and Start agree, without
	// actually running the trampoline: check that the expected tier string is NOT
	// "tier0" on a system where selectTier returns "landlock".
	_ = self
	expectedTier := selectTier(detectBwrap(), usernsRestricted())

	r := &linuxRunner{}
	sess, err := r.Start(context.Background(), Spec{
		Command: "/bin/cat",
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Skipf("linuxRunner.Start unavailable (trampoline not compiled in): %v", err)
	}
	defer sess.Close()

	got := sess.Tier()
	if got == "tier0" {
		t.Errorf("Session.Tier() = %q (hardcoded tier0 leaked through); want %q", got, expectedTier)
	}
	if got != expectedTier {
		t.Errorf("Session.Tier() = %q, want %q", got, expectedTier)
	}
}

// TestSelectTier_AlwaysLandlock verifies that selectTier always returns
// "landlock" regardless of whether bwrap is on PATH or userns is restricted.
// bwrap is never exec'd by the runner (SBX-9c), so the tier must never be "bwrap".
func TestSelectTier_AlwaysLandlock(t *testing.T) {
	cases := []struct {
		bwrapPath        string
		usernsRestricted bool
	}{
		{"", false},
		{"", true},
		{"/usr/bin/bwrap", false},
		{"/usr/bin/bwrap", true},
	}
	for _, tc := range cases {
		got := selectTier(tc.bwrapPath, tc.usernsRestricted)
		if got != "landlock" {
			t.Errorf("selectTier(%q, %v) = %q; want landlock", tc.bwrapPath, tc.usernsRestricted, got)
		}
	}
}

// TestRunSandboxChild_ExecsAndIsolates runs THIS test binary as the trampoline
// child so we exercise the real RunSandboxChild -> applyChildLimits ->
// applyLandlock -> syscall.Exec path end to end, then assert the exec'd command
// could NOT read a denied $HOME file.
//
// The `__mcp-sandbox-child` dispatch is handled by TestMain (testmain_test.go)
// BEFORE the test framework boots, so Landlock is applied ONLY in the throwaway
// subprocess — never in this test process. We therefore must NOT call
// landlockStrictSupported here (it would apply Landlock in-process and corrupt
// the test process / OOM the race detector). Instead we gate on the read-only
// kernel ABI query and let the child's own applied= marker tell us whether
// confinement actually took effect.
func TestRunSandboxChild_ExecsAndIsolates(t *testing.T) {
	if kernelLandlockABI() == 0 {
		t.Skip("Landlock not supported on this kernel; trampoline isolation skipped")
	}

	home := t.TempDir()
	secret := home + "/secret.txt"
	if err := os.WriteFile(secret, []byte("token"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	tmp := t.TempDir()

	// Re-exec this test binary as the child; the "real command" it execs is
	// `cat <secret>`, which must FAIL because $HOME is denied by Landlock.
	// TestMain dispatches the trampoline before m.Run(), so no test code runs in
	// this child.
	cmd := exec.Command(os.Args[0],
		"__mcp-sandbox-child", tmp, home, "", "--", "cat", secret)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	combined := string(out)

	// The child must always print the applied marker on its real stderr.
	if !strings.Contains(combined, "keelix-sandbox: applied=") {
		t.Fatalf("expected applied marker in child stderr, got: %q", combined)
	}
	// If Landlock genuinely applied, the $HOME read MUST have been denied.
	if strings.Contains(combined, "keelix-sandbox: applied=true") {
		if err == nil && strings.Contains(combined, "token") {
			t.Fatalf("expected denied $HOME read under applied Landlock, but child cat succeeded: %q", combined)
		}
		return
	}
	// applied=false: BestEffort degraded to a no-op on this kernel; the deny-home
	// guarantee can't be asserted. Don't paper over it — just don't hard-fail.
	t.Skip("child reported applied=false (Landlock degraded); deny-home assertion skipped")
}

// TestRoCaches_RejectsInjectedSSHPath is a security test (SBX-4): a config env
// that sets npm_config_cache to $HOME/.ssh must NOT be added to the Landlock
// RODirs allowlist — doing so would re-grant read access to the user's secrets.
func TestRoCaches_RejectsInjectedSSHPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	injected := filepath.Join(home, ".ssh")
	env := map[string]string{
		"npm_config_cache": injected,
	}
	caches := roCaches(env)
	for _, c := range caches {
		if c == injected || strings.HasPrefix(c, injected) {
			t.Errorf("roCaches accepted injected path %q (must be rejected to prevent HOME read bypass)", c)
		}
	}
}

// TestRoCaches_AcceptsDefaultNpmCache verifies that the npm default cache
// directory (~/.npm) IS accepted by roCaches, so npx can resolve packages.
func TestRoCaches_AcceptsDefaultNpmCache(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	npmCache := filepath.Join(home, ".npm")
	env := map[string]string{
		"npm_config_cache": npmCache,
	}
	caches := roCaches(env)
	found := false
	for _, c := range caches {
		if c == npmCache {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("roCaches rejected %q (default npm cache should be accepted)", npmCache)
	}
}

// TestRoCaches_AcceptsDefaultUvCache verifies that the uvx default cache dir
// (~/.cache/uv or /tmp) passes the allowlist check.
func TestRoCaches_AcceptsDefaultUvCache(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	uvCache := filepath.Join(home, ".cache", "uv")
	env := map[string]string{
		"UV_CACHE_DIR": uvCache,
	}
	caches := roCaches(env)
	found := false
	for _, c := range caches {
		if c == uvCache {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("roCaches rejected %q (default uv cache should be accepted)", uvCache)
	}
}

// TestRoCaches_RejectsTmpSubdirAmbiguousHomeChild verifies that a path like
// $HOME/randomdir (not under a known cache root) is rejected even when it
// doesn't look immediately dangerous.
func TestRoCaches_RejectsArbitraryHomeSubdir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	arbitrary := filepath.Join(home, "projects", "secret")
	env := map[string]string{
		"UV_CACHE_DIR": arbitrary,
	}
	caches := roCaches(env)
	for _, c := range caches {
		if c == arbitrary || strings.HasPrefix(c, arbitrary) {
			t.Errorf("roCaches accepted arbitrary HOME subpath %q (should be rejected)", c)
		}
	}
}

// TestAllowedCachePath_KnownRootsAccepted verifies that allowedCachePath
// accepts paths exactly equal to or under the known safe cache roots.
func TestAllowedCachePath_KnownRootsAccepted(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	accepted := []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".npm", "subdir"),
		filepath.Join(home, ".cache"),
		filepath.Join(home, ".cache", "uv"),
		filepath.Join(home, ".cache", "uv", "pkg"),
		"/tmp",
		"/tmp/somecache",
	}
	for _, p := range accepted {
		if !allowedCachePath(p) {
			t.Errorf("allowedCachePath(%q) = false, want true", p)
		}
	}
}

// TestAllowedCachePath_DangerousPathsRejected verifies that allowedCachePath
// rejects paths outside the known safe cache roots.
func TestAllowedCachePath_DangerousPathsRejected(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	rejected := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config"),
		home,
		filepath.Join(home, "projects"),
		"/etc",
		"/var",
		"/home",
		"/root",
	}
	for _, p := range rejected {
		if allowedCachePath(p) {
			t.Errorf("allowedCachePath(%q) = true, want false (should be rejected)", p)
		}
	}
}
