//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// probeResult holds what a single trampoline-child + __landlock-probe run
// reported. It is produced by runLandlockProbeChild, which applies Landlock ONLY
// inside the throwaway subprocess — never in the test process (Landlock is
// per-process sticky and would corrupt the runner / OOM the race detector).
type probeResult struct {
	applied      bool   // child's applied= marker (Landlock actually enforced)
	netConfined  bool   // child's net-confined= marker (ABI >=4 TCP denial)
	homeRead     string // "denied" | "allowed"
	tempWrite    string // "ok" | "fail"
	tcpDial      string // "denied" | "refused" | "allowed"
	nnp          string // PR_GET_NO_NEW_PRIVS readback in the child ("0"|"1"|...)
	rlimitNofile string // RLIMIT_NOFILE cur observed in the child
	raw          string // combined stdout+stderr, for diagnostics
}

// runLandlockProbeChild re-execs THIS test binary as the trampoline child
// (`__mcp-sandbox-child <tmp> <home> "" -- <self> __landlock-probe <home> <tmp>`).
// TestMain dispatches __mcp-sandbox-child, which applies Landlock+rlimits and
// syscall.Exec's the inner `__landlock-probe` command, which TestMain also
// dispatches. Everything sticky happens in this disposable subprocess.
func runLandlockProbeChild(t *testing.T, home, tmp string) probeResult {
	t.Helper()
	self := os.Args[0]
	cmd := exec.Command(self,
		"__mcp-sandbox-child", tmp, home, "", "--",
		self, "__landlock-probe", home, tmp)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, _ := cmd.CombinedOutput() // exit code is not load-bearing; we parse lines
	combined := string(out)
	res := probeResult{raw: combined}
	for _, line := range strings.Split(combined, "\n") {
		s := strings.TrimSpace(line)
		switch {
		case s == "keelix-sandbox: applied=true":
			res.applied = true
		case s == "keelix-sandbox: net-confined=true":
			res.netConfined = true
		case strings.HasPrefix(s, "PROBE: home-read="):
			res.homeRead = strings.TrimPrefix(s, "PROBE: home-read=")
		case strings.HasPrefix(s, "PROBE: temp-write="):
			res.tempWrite = strings.TrimPrefix(s, "PROBE: temp-write=")
		case strings.HasPrefix(s, "PROBE: tcp-dial="):
			res.tcpDial = strings.TrimPrefix(s, "PROBE: tcp-dial=")
		case strings.HasPrefix(s, "PROBE: nnp="):
			res.nnp = strings.TrimPrefix(s, "PROBE: nnp=")
		case strings.HasPrefix(s, "PROBE: rlimit-nofile="):
			res.rlimitNofile = strings.TrimPrefix(s, "PROBE: rlimit-nofile=")
		}
	}
	if !strings.Contains(combined, "keelix-sandbox: applied=") {
		t.Fatalf("trampoline child produced no applied marker; output:\n%s", combined)
	}
	return res
}

// TestApplyLandlock_DeniesHomeReadWhenEnforced verifies the deny-$HOME guarantee
// (and that the RW tempdir stays writable) via a SUBPROCESS. Landlock is
// per-process sticky, so it must NEVER be applied in the test process — doing so
// denies later t.TempDir() mkdirs and OOMs the -race ThreadSanitizer. We drive a
// throwaway trampoline child instead and assert on what it reports.
func TestApplyLandlock_DeniesHomeReadWhenEnforced(t *testing.T) {
	if kernelLandlockABI() == 0 {
		t.Skip("Landlock not supported on this kernel; deny-home assertion skipped")
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "secret.txt"), []byte("token"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	tmp := t.TempDir()

	res := runLandlockProbeChild(t, home, tmp)
	if !res.applied {
		t.Skipf("child reported Landlock degraded (applied=false); deny-home assertion skipped. output:\n%s", res.raw)
	}
	// $HOME is excluded from RODirs, so the read must have been denied.
	if res.homeRead != "denied" {
		t.Fatalf("expected $HOME read denied under Landlock, got home-read=%q; output:\n%s", res.homeRead, res.raw)
	}
	// The RW tempdir must still be writable inside the sandbox.
	if res.tempWrite != "ok" {
		t.Fatalf("expected RW tempdir to stay writable, got temp-write=%q; output:\n%s", res.tempWrite, res.raw)
	}
}

// TestApplyChildLimits_SetsNoNewPrivsAndRlimits verifies the no-exec core of the
// trampoline (NO_NEW_PRIVS + rlimits) from a SUBPROCESS. applyChildLimits is
// sticky and corrupts the caller: RLIMIT_CPU=10s SIGXCPU-kills a long -race run.
// (RLIMIT_AS and RLIMIT_NPROC are intentionally no longer applied — RLIMIT_AS
// would have starved the ThreadSanitizer's huge virtual reservation and the
// per-uid RLIMIT_NPROC would have blocked its thread creation; see limits.go.)
// So it must NOT run in the test process. The trampoline child runs applyChildLimits on itself
// before exec'ing the probe, which reads the values back for us.
func TestApplyChildLimits_SetsNoNewPrivsAndRlimits(t *testing.T) {
	if kernelLandlockABI() == 0 {
		t.Skip("Landlock not supported on this kernel; trampoline child unavailable")
	}
	home := t.TempDir()
	tmp := t.TempDir()

	res := runLandlockProbeChild(t, home, tmp)

	// PR_SET_NO_NEW_PRIVS is applied by applyChildLimits unconditionally (it does
	// not depend on Landlock), so assert it regardless of applied=.
	if res.nnp != "1" {
		t.Fatalf("NO_NEW_PRIVS not set in child, got nnp=%q; output:\n%s", res.nnp, res.raw)
	}
	want := strconv.FormatUint(DefaultLimits().NoFile, 10)
	if res.rlimitNofile != want {
		t.Fatalf("RLIMIT_NOFILE cur=%q want %q; output:\n%s", res.rlimitNofile, want, res.raw)
	}
	if !strings.Contains(res.rlimitNofile, "1024") {
		t.Fatalf("sanity: NoFile default expected 1024, got %q", res.rlimitNofile)
	}
}

func TestSandboxAppliedMarker_RoundTrips(t *testing.T) {
	if got := sandboxAppliedMarker(true); got != "keelix-sandbox: applied=true" {
		t.Fatalf("marker(true)=%q", got)
	}
	if got := sandboxAppliedMarker(false); got != "keelix-sandbox: applied=false" {
		t.Fatalf("marker(false)=%q", got)
	}
	if !parseAppliedMarker([]byte("noise\nkeelix-sandbox: applied=true\nmore\n")) {
		t.Fatalf("expected applied=true parsed from stderr")
	}
	if parseAppliedMarker([]byte("keelix-sandbox: applied=false\n")) {
		t.Fatalf("expected applied=false parsed from stderr")
	}
	if parseAppliedMarker([]byte("no marker here")) {
		t.Fatalf("absent marker must read as not-applied")
	}
}

// TestNetConfinedMarker_RoundTrips verifies the net-confined marker
// encode/parse cycle for both true and false states, and that an absent
// marker safely defaults to false.
func TestNetConfinedMarker_RoundTrips(t *testing.T) {
	if got := sandboxNetConfinedMarker(true); got != "keelix-sandbox: net-confined=true" {
		t.Fatalf("netConfinedMarker(true)=%q", got)
	}
	if got := sandboxNetConfinedMarker(false); got != "keelix-sandbox: net-confined=false" {
		t.Fatalf("netConfinedMarker(false)=%q", got)
	}
	// Parse true from multi-line stderr.
	if !parseNetConfinedMarker([]byte("keelix-sandbox: applied=true\nkeelix-sandbox: net-confined=true\n")) {
		t.Fatalf("expected net-confined=true parsed from stderr")
	}
	// Parse false from multi-line stderr.
	if parseNetConfinedMarker([]byte("keelix-sandbox: applied=true\nkeelix-sandbox: net-confined=false\n")) {
		t.Fatalf("expected net-confined=false parsed from stderr")
	}
	// Absent marker defaults to false (safe: assume not confined).
	if parseNetConfinedMarker([]byte("no marker here")) {
		t.Fatalf("absent net-confined marker must default to false")
	}
}

// TestKernelLandlockABI_MatchesSyscall verifies that kernelLandlockABI() agrees
// with the raw LandlockGetABIVersion() syscall. This test always runs (no skip)
// because the function simply queries the kernel; if Landlock is not supported
// both sides return 0 and that is fine.
func TestKernelLandlockABI_MatchesSyscall(t *testing.T) {
	want, err := llsyscall.LandlockGetABIVersion()
	if err != nil {
		want = 0
	}
	got := kernelLandlockABI()
	if got != want {
		t.Fatalf("kernelLandlockABI()=%d, want %d (from LandlockGetABIVersion)", got, want)
	}
}

// TestApplyLandlock_NetConfinedFlagReflectsABI verifies that the trampoline
// child's net-confined= marker is true only when the kernel's Landlock ABI is
// >=4 (kernel >=6.7), and false on ABI <4. The assertion is driven from a
// SUBPROCESS — applyLandlock is never called in the test process (Landlock is
// sticky). The expected value is derived from the read-only ABI query at
// runtime, so it runs on all kernel versions that have any Landlock support.
func TestApplyLandlock_NetConfinedFlagReflectsABI(t *testing.T) {
	if kernelLandlockABI() == 0 {
		t.Skip("Landlock not supported on this kernel; cannot assert netConfined ABI logic")
	}
	home := t.TempDir()
	tmp := t.TempDir()

	res := runLandlockProbeChild(t, home, tmp)
	if !res.applied {
		t.Skipf("child reported Landlock degraded (applied=false); netConfined assertion skipped. output:\n%s", res.raw)
	}

	// Expected: net-confined iff the kernel supports ABI >=4.
	wantNetConfined := kernelLandlockABI() >= 4
	if res.netConfined != wantNetConfined {
		t.Fatalf("child net-confined=%v but kernel ABI>=4 is %v: "+
			"applyLandlock must honestly reflect whether RestrictNet() enforced TCP denial. output:\n%s",
			res.netConfined, wantNetConfined, res.raw)
	}
}

// TestApplyLandlock_NetworkDeniedOnABI4Plus verifies the actual security
// guarantee: after applyLandlock on a kernel with Landlock ABI >=4, an outbound
// TCP connection must be denied. The assertion is driven from a SUBPROCESS (the
// trampoline child applies Landlock then exec's a TCP-dial probe) — Landlock is
// never applied in the test process. On kernels with ABI <4 the test skips:
// network confinement is genuinely absent and the goal is to be honest about it.
//
// On a real kernel with Landlock ABI >=4 (Linux 6.7+) this is NOT skipped:
// network denial is a security guarantee and must be verified for real.
func TestApplyLandlock_NetworkDeniedOnABI4Plus(t *testing.T) {
	if kernelLandlockABI() < 4 {
		t.Skip("Landlock ABI <4 (kernel <6.7): network confinement not available; skipping net-deny assertion")
	}
	home := t.TempDir()
	tmp := t.TempDir()

	res := runLandlockProbeChild(t, home, tmp)
	if !res.applied {
		t.Fatalf("ABI >=4 detected but child reported applied=false; internal isolation bug. output:\n%s", res.raw)
	}
	if !res.netConfined {
		t.Fatalf("ABI >=4 detected but child reported net-confined=false; internal ABI detection bug. output:\n%s", res.raw)
	}

	// The probe dialed 127.0.0.1:1 (nothing listening). Under Landlock net-deny
	// the connect() syscall is blocked (EACCES/EPERM) => "denied". ECONNREFUSED
	// ("refused") would mean the syscall reached the network stack — a bypass.
	switch res.tcpDial {
	case "denied":
		// expected: Landlock blocked the connect() syscall.
	case "refused":
		t.Fatalf("TCP connect got ECONNREFUSED instead of EACCES/EPERM: "+
			"Landlock net-deny did NOT prevent the connect() syscall. output:\n%s", res.raw)
	case "allowed":
		t.Fatalf("expected TCP dial to fail under Landlock net-deny, but it succeeded. output:\n%s", res.raw)
	default:
		t.Fatalf("unexpected tcp-dial probe result %q; output:\n%s", res.tcpDial, res.raw)
	}
}
