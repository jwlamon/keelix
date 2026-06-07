//go:build darwin

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// darwinRunner isolates the probe with Seatbelt (sandbox-exec) wrapped around
// the Tier-0 baseRunner. baseRunner still owns the clean env, the tempdir cwd,
// the process-group teardown and the output cap; this runner adds kernel-level
// file/network confinement and rlimits on top, and reports the tier honestly.
type darwinRunner struct {
	baseRunner
}

// newDarwinRunner is the platform constructor selected by NewRunner() on darwin
// (see sandbox.go in SLICE-SLA).
func newDarwinRunner() Runner { return &darwinRunner{} }

// shQuote single-quotes an argument for POSIX /bin/sh, escaping embedded quotes.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// wrapDarwinSpec rewrites a Spec so its command runs under sandbox-exec with a
// ulimit prefix. sandboxExecPath is the resolved path to sandbox-exec, or ""
// when it is unavailable. On "" it returns the Spec UNCHANGED and tier="tier0"
// applied=false, so the caller runs the bare command under Tier-0 only.
func wrapDarwinSpec(s Spec, sandboxExecPath string) (Spec, string, bool) {
	if sandboxExecPath == "" {
		return s, "tier0", false
	}

	// Resolve the system temp root so Seatbelt subpath matching (which does not
	// follow symlinks) actually permits writes into whatever tempdir baseRunner
	// creates underneath it. Falls back to the unresolved root on error.
	writableRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		writableRoot = os.TempDir()
	}
	// SBX-4: collect validated cache paths from Spec.Env so allowedCachePath
	// filters out any injected path (e.g. npm_config_cache=~/.ssh) before it
	// can appear as a Seatbelt subpath allow.
	caches := roCaches(s.Env)
	profile := seatbeltProfile(writableRoot, caches)

	// Build: ulimit ...; exec '<sandbox-exec>' -p '<profile>' '<cmd>' '<args>'...
	parts := []string{shQuote(sandboxExecPath), "-p", shQuote(profile), shQuote(s.Command)}
	for _, a := range s.Args {
		parts = append(parts, shQuote(a))
	}
	script := ulimitPrefix(DefaultLimits()) + "exec " + strings.Join(parts, " ")

	out := s
	out.Command = "/bin/sh"
	out.Args = []string{"-c", script}
	return out, "seatbelt", true
}

// lookupSandboxExec returns the path to sandbox-exec, or "" if it is missing.
func lookupSandboxExec() string {
	if p, err := exec.LookPath("sandbox-exec"); err == nil {
		return p
	}
	return ""
}

// Run wraps the command in Seatbelt then delegates to the Tier-0 baseRunner,
// overriding the reported Tier/SandboxApplied to reflect this layer.
func (r *darwinRunner) Run(ctx context.Context, s Spec) (*Result, error) {
	wrapped, tier, applied := wrapDarwinSpec(s, lookupSandboxExec())
	res, err := r.baseRunner.Run(ctx, wrapped)
	if res != nil {
		res.Tier = tier
		res.SandboxApplied = applied
		if applied {
			res.Notes = append(res.Notes, "isolated under Seatbelt (sandbox-exec) deny-network; rlimits via ulimit")
		} else {
			res.Notes = append(res.Notes, "sandbox-exec unavailable: Tier-0 baseline only (no kernel isolation)")
		}
	}
	return res, err
}

// Start is the streaming entrypoint used by the stdio MCP transport (SLD). It
// applies the same Seatbelt wrap, then delegates to baseRunner.Start and
// overwrites the hardcoded "tier0" that baseRunner stores with the real tier
// and applied flag returned by wrapDarwinSpec (mirrors the fix in
// runner_linux.go and closes the SBX-1 honest-applied gap on darwin).
func (r *darwinRunner) Start(ctx context.Context, s Spec) (Session, error) {
	wrapped, tier, applied := wrapDarwinSpec(s, lookupSandboxExec())
	sess, err := r.baseRunner.Start(ctx, wrapped)
	if err != nil {
		return nil, err
	}
	// Overwrite the Tier-0 defaults that baseRunner.Start stores; the darwin
	// runner has already selected the real isolation tier and knows whether
	// Seatbelt actually engaged (sandbox-exec was found on PATH).
	sess.(*baseSession).tier = tier
	sess.(*baseSession).applied = applied
	return sess, nil
}

// compile-time guard that we satisfy the interface (also documents intent).
var _ Runner = (*darwinRunner)(nil)

// (fmt is imported for future profile diagnostics; reference it to avoid an
// unused-import error if the diagnostics line is trimmed.)
var _ = fmt.Sprintf

// NewRunner returns the strongest sandbox Runner the host supports. On darwin
// the darwinRunner wraps baseRunner with a Seatbelt profile + rlimits via ulimit.
func NewRunner() Runner {
	return newDarwinRunner()
}
