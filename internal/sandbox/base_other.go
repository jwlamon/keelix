//go:build !linux && !darwin

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
)

// tempDirPattern is the prefix for every sandbox working directory; tests key
// on it to confirm the child ran inside a throwaway dir.
const tempDirPattern = "keelix-sbx-*"

// baseRunner is the Tier-0 fallback for unsupported platforms. It applies the
// process-level hygiene that does not depend on POSIX APIs: clean env,
// throwaway cwd, and output caps. Group-kill and Setpgid are omitted because
// they are not portable; the linux and darwin builds (base.go) include those
// POSIX extensions.
type baseRunner struct{}

// cleanEnv builds the child environment from ONLY s.Env plus a minimal PATH
// and a HOME pointing at the throwaway tempdir.
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
	sort.Strings(keys)
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

// buildCmd constructs the child command without POSIX process-group support.
func (r *baseRunner) buildCmd(ctx context.Context, s Spec, home string) (*exec.Cmd, string, bool) {
	cmd := exec.CommandContext(ctx, s.Command, s.Args...) // #nosec G204
	cmd.Dir = home
	cmd.Env = cleanEnv(s, home)
	return cmd, "tier0", false
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

	waitErr := cmd.Wait()

	res.Stdout = outBuf.Bytes()
	res.Stderr = errBuf.Bytes()
	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	res.ExitCode = exitCode(waitErr)
	return res, nil
}

// exitCode extracts a numeric exit code from cmd.Wait's error.
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

// capWriter writes at most cap bytes to the underlying buffer and silently
// discards the rest.
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
		return len(p), nil
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

// Start launches a streaming session.
func (r *baseRunner) Start(ctx context.Context, s Spec) (Session, error) {
	home, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		return nil, fmt.Errorf("sandbox tempdir: %w", err)
	}

	cctx := ctx
	var cancel context.CancelFunc
	if s.Timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, s.Timeout)
	}

	cmd, tier, _ := r.buildCmd(cctx, s, home)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		cleanupStart(home, cancel)
		return nil, fmt.Errorf("sandbox stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cleanupStart(home, cancel)
		return nil, fmt.Errorf("sandbox stdout pipe: %w", err)
	}
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		cleanupStart(home, cancel)
		return nil, fmt.Errorf("sandbox start: %w", err)
	}

	return &baseSession{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		tier:   tier,
		home:   home,
		cancel: cancel,
	}, nil
}

// cleanupStart releases resources when Start aborts before returning a Session.
func cleanupStart(home string, cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
	_ = os.RemoveAll(home)
}

// baseSession is the Tier-0 streaming child for non-POSIX platforms.
type baseSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	tier   string
	home   string
	cancel context.CancelFunc

	closeOnce sync.Once
	closeErr  error
}

func (s *baseSession) Stdin() io.Writer  { return s.stdin }
func (s *baseSession) Stdout() io.Reader { return s.stdout }
func (s *baseSession) Tier() string      { return s.tier }

// Applied always returns false on non-POSIX platforms: no kernel confinement
// (Landlock / Seatbelt) is available, so only Tier-0 process hygiene applies.
func (s *baseSession) Applied() bool { return false }

// Close terminates the child and removes the tempdir.
func (s *baseSession) Close() error {
	s.closeOnce.Do(func() {
		_ = s.stdin.Close()
		if s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		if s.cancel != nil {
			s.cancel()
		}
		s.closeErr = s.cmd.Wait()
		_ = s.stdout.Close()
		_ = os.RemoveAll(s.home)
	})
	return s.closeErr
}
