//go:build linux || darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
)

// tempDirPattern is the prefix for every sandbox working directory; tests key
// on it to confirm the child ran inside a throwaway dir.
const tempDirPattern = "keelix-sbx-*"

// baseRunner is the Tier-0 cross-platform runner: it applies the
// process-level hygiene that needs no kernel support (clean env, throwaway
// cwd, own process group, output caps, hard timeout). The linux and darwin
// runners EMBED it and override only the command-construction step.
type baseRunner struct{}

// cleanEnv builds the child environment from ONLY s.Env plus a minimal PATH
// and a HOME pointing at the throwaway tempdir. It NEVER copies os.Environ(),
// so secrets in the parent process cannot leak to untrusted MCP code.
func cleanEnv(s Spec, home string) []string {
	env := map[string]string{
		"PATH": "/usr/local/bin:/usr/bin:/bin",
		"HOME": home,
	}
	for k, v := range s.Env {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic ordering for tests
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

// outputCap returns the effective per-stream byte cap for s.
func outputCap(s Spec) int64 {
	if s.OutputCap > 0 {
		return s.OutputCap
	}
	return defaultOutputCap
}

// buildCmd is the per-tier spawn seam. The Tier-0 baseRunner runs the command
// directly; linux/darwin override this to wrap/re-exec with confinement. It
// returns the *exec.Cmd (cwd, env, and pgid already set) and the chosen tier.
func (r *baseRunner) buildCmd(ctx context.Context, s Spec, home string) (*exec.Cmd, string, bool) {
	cmd := exec.CommandContext(ctx, s.Command, s.Args...) // #nosec G204 -- the command is the operator-consented MCP server from their own config; the whole point is to execute it sandboxed
	cmd.Dir = home
	cmd.Env = cleanEnv(s, home)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd, "tier0", false
}

// workDir creates a throwaway tempdir for a sandboxed child.
// It is the seam consumed by the linux and darwin platform runners so they can
// separate "create the dir" from "run the command inside it".
func (r *baseRunner) workDir() (string, error) {
	d, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		return "", fmt.Errorf("sandbox tempdir: %w", err)
	}
	return d, nil
}

// cleanup removes the tempdir created by workDir. It is safe to call with an
// empty path (no-op).
func (r *baseRunner) cleanup(workdir string) {
	if workdir != "" {
		_ = os.RemoveAll(workdir)
	}
}

// runIn executes s to completion inside an already-created workdir and returns
// the Result, the child pid (for belt-and-suspenders Prlimit), and any error.
// The pid is 0 if the child could not be started.
func (r *baseRunner) runIn(ctx context.Context, s Spec, workdir string) (*Result, int, error) {
	cctx := ctx
	var cancel context.CancelFunc
	if s.Timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	cmd, tier, applied := r.buildCmd(cctx, s, workdir)
	res := &Result{Tier: tier, SandboxApplied: applied}

	cap := outputCap(s)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &capWriter{w: &outBuf, cap: cap}
	cmd.Stderr = &capWriter{w: &errBuf, cap: cap}

	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("sandbox start: %w", err)
	}
	pid := cmd.Process.Pid

	done := make(chan struct{})
	go func() {
		select {
		case <-cctx.Done():
			killGroup(cmd)
		case <-done:
		}
	}()

	waitErr := cmd.Wait()
	close(done)

	res.Stdout = outBuf.Bytes()
	res.Stderr = errBuf.Bytes()
	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	res.ExitCode = exitCode(waitErr)
	return res, pid, nil
}

// startIn launches s as a streaming child inside workdir and returns the
// Session and the child pid (for Prlimit). On error the workdir is NOT cleaned
// up — the caller must call cleanup.
//
// When the child writes an applied-marker as its first stderr line (the linux
// trampoline does this), we capture that line via a stderr pipe before handing
// the rest of stderr to io.Discard. The goroutine sets sess.applied once the
// marker is read, so callers that need Applied() must wait until the child has
// had a chance to print it (the JSON-RPC handshake naturally provides that
// window). appliedCh is closed after the marker goroutine finishes.
func (r *baseRunner) startIn(ctx context.Context, s Spec, workdir string) (Session, int, error) {
	cctx := ctx
	var cancel context.CancelFunc
	if s.Timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, s.Timeout)
	}

	cmd, tier, buildApplied := r.buildCmd(cctx, s, workdir)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, 0, fmt.Errorf("sandbox stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, 0, fmt.Errorf("sandbox stdout pipe: %w", err)
	}

	// Capture stderr via a pipe so the marker goroutine can read the first line.
	// For Tier-0 (no trampoline) the child produces no marker; the goroutine
	// drains stderr silently and buildApplied (false) is the answer.
	stderrR, stderrW, pipeErr := os.Pipe()
	if pipeErr != nil {
		// Fallback: discard stderr; applied stays at buildApplied.
		cmd.Stderr = io.Discard
	} else {
		cmd.Stderr = stderrW
	}

	if err := cmd.Start(); err != nil {
		if cancel != nil {
			cancel()
		}
		if stderrR != nil {
			_ = stderrR.Close()
			_ = stderrW.Close()
		}
		return nil, 0, fmt.Errorf("sandbox start: %w", err)
	}
	// Close the write end in the parent — the child holds the only write end now.
	if stderrW != nil {
		_ = stderrW.Close()
	}
	pid := cmd.Process.Pid

	sess := &baseSession{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		tier:    tier,
		applied: buildApplied, // overridden below if a marker pipe was set up
		home:    workdir,
		cancel:  cancel,
	}

	// Launch a goroutine to read the first stderr line (the applied marker) and
	// then drain the rest. We do NOT block startIn — the probe's JSON-RPC
	// handshake provides enough time for the trampoline to print the marker
	// before the caller first calls Applied().
	if stderrR != nil {
		appliedCh := make(chan bool, 1)
		sess.appliedCh = appliedCh
		go func() {
			defer stderrR.Close()
			buf := make([]byte, 512)
			var line []byte
			// Read byte-by-byte until newline to avoid consuming stdout-bound data.
			// In practice the marker is <=64 bytes; cap at 512 to be safe.
			for len(line) < 512 {
				n, err := stderrR.Read(buf[:1])
				if n > 0 {
					if buf[0] == '\n' {
						break
					}
					line = append(line, buf[0])
				}
				if err != nil {
					break
				}
			}
			// Parse the marker; keep buildApplied when absent (Tier-0 / no trampoline).
			markerApplied := parseAppliedMarkerLine(string(line))
			if markerApplied != nil {
				appliedCh <- *markerApplied
			} else {
				appliedCh <- buildApplied
			}
			close(appliedCh)
			// Drain remaining stderr so the child is never blocked on a full pipe.
			_, _ = io.Copy(io.Discard, stderrR)
		}()
	}

	if s.Timeout > 0 {
		sess.done = make(chan struct{})
		go func() {
			select {
			case <-cctx.Done():
				killGroup(cmd)
			case <-sess.done:
			}
		}()
	}

	return sess, pid, nil
}

// Run executes s to completion under Tier-0 hygiene and returns its Result.
func (r *baseRunner) Run(ctx context.Context, s Spec) (*Result, error) {
	home, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		return nil, fmt.Errorf("sandbox tempdir: %w", err)
	}
	defer os.RemoveAll(home)

	cctx := ctx
	var cancel context.CancelFunc
	if s.Timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}

	cmd, tier, applied := r.buildCmd(cctx, s, home)
	res := &Result{Tier: tier, SandboxApplied: applied}

	cap := outputCap(s)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &capWriter{w: &outBuf, cap: cap}
	cmd.Stderr = &capWriter{w: &errBuf, cap: cap}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sandbox start: %w", err)
	}

	// Kill the WHOLE process group on ctx cancel/timeout, not just the leader,
	// so a child that forked grandchildren cannot survive.
	done := make(chan struct{})
	go func() {
		select {
		case <-cctx.Done():
			killGroup(cmd)
		case <-done:
		}
	}()

	waitErr := cmd.Wait()
	close(done)

	res.Stdout = outBuf.Bytes()
	res.Stderr = errBuf.Bytes()
	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	res.ExitCode = exitCode(waitErr)
	return res, nil
}

// killGroup sends SIGKILL to the child's entire process group (negative pid).
func killGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		// Fall back to killing just the leader.
		_ = cmd.Process.Kill()
		return
	}
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}

// exitCode extracts a numeric exit code from cmd.Wait's error. A nil error is
// 0; a signal-kill (group timeout) reports -1; other start/IO errors report 1.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}

// markerLinePrefix is the prefix the trampoline child writes to stderr so the
// parent can verify whether kernel isolation actually engaged. It is defined
// here (not in child_linux.go) so base.go's startIn can parse it on all
// supported platforms without a build-tag gap.
const markerLinePrefix = "keelix-sandbox: applied="

// parseAppliedMarkerLine parses a single trimmed stderr line and returns the
// applied value when the line matches the marker prefix. Returns nil when the
// line is not a marker (absent trampoline, Tier-0, darwin Seatbelt path).
func parseAppliedMarkerLine(line string) *bool {
	if line == markerLinePrefix+"true" {
		v := true
		return &v
	}
	if line == markerLinePrefix+"false" {
		v := false
		return &v
	}
	return nil
}

// capWriter writes at most cap bytes to the underlying buffer and silently
// discards the rest, so a child flooding stdout cannot exhaust memory.
type capWriter struct {
	mu      sync.Mutex
	w       io.Writer
	cap     int64
	written int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := c.cap - c.written
	if remaining <= 0 {
		return len(p), nil // pretend success; discard
	}
	if int64(len(p)) > remaining {
		_, _ = c.w.Write(p[:remaining])
		c.written = c.cap
		return len(p), nil
	}
	n, err := c.w.Write(p)
	c.written += int64(n)
	return n, err
}
