//go:build linux || darwin

package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// baseSession is the Tier-0 streaming child. It owns the throwaway tempdir and
// the child's process group; Close kills the whole group and removes the dir.
// The linux/darwin runners reuse it verbatim — only buildCmd differs.
type baseSession struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	tier    string
	applied bool // true only when real kernel confinement (Landlock/Seatbelt) engaged
	home    string
	cancel  context.CancelFunc

	// appliedCh, when non-nil, carries the definitive applied value from the
	// trampoline marker goroutine (linux Start path). Applied() blocks on it
	// exactly once then caches the result. For Tier-0 and darwin paths it is nil.
	appliedCh chan bool

	// done is closed by Close to stop the timeout-watchdog goroutine.
	done chan struct{}

	closeOnce sync.Once
	closeErr  error
}

func (s *baseSession) Stdin() io.Writer  { return s.stdin }
func (s *baseSession) Stdout() io.Reader { return s.stdout }
func (s *baseSession) Tier() string      { return s.tier }

// Applied reports whether real kernel confinement (Landlock / Seatbelt) was
// verified to have taken effect. On the linux streaming path this blocks
// briefly until the trampoline child's first stderr line (the applied-marker)
// has been read by the background goroutine; on all other paths it returns
// the value set at session creation.
func (s *baseSession) Applied() bool {
	if s.appliedCh != nil {
		if v, ok := <-s.appliedCh; ok {
			s.applied = v
		}
		s.appliedCh = nil // drain only once; subsequent calls return cached value
	}
	return s.applied
}

// Close terminates the child's process group, waits for it, and removes the
// tempdir. It is safe to call more than once.
func (s *baseSession) Close() error {
	s.closeOnce.Do(func() {
		// Signal the timeout-watchdog goroutine (if any) to stop.
		if s.done != nil {
			close(s.done)
		}
		_ = s.stdin.Close()
		killGroup(s.cmd)
		if s.cancel != nil {
			s.cancel()
		}
		s.closeErr = s.cmd.Wait()
		_ = s.stdout.Close()
		_ = os.RemoveAll(s.home)
	})
	return s.closeErr
}

// Start launches s as a streaming child under Tier-0 hygiene and returns a
// Session whose Stdin/Stdout the caller drives (SLD's stdio JSON-RPC).
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
	// stderr is discarded for streaming sessions; the protocol lives on stdout.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		cleanupStart(home, cancel)
		return nil, fmt.Errorf("sandbox start: %w", err)
	}

	sess := &baseSession{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
		tier:   tier,
		home:   home,
		cancel: cancel,
	}

	// Mirror the Run() pattern: when a timeout is set, launch a watchdog
	// goroutine that kills the WHOLE process group (not just the leader) when
	// the context deadline fires. exec.CommandContext's default Cancel only
	// calls cmd.Process.Kill() on the leader, so forked grandchildren survive
	// until the caller eventually calls Close(). The goroutine exits early if
	// Close() is called first (it closes sess.done).
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

	return sess, nil
}

// cleanupStart releases resources when Start aborts before returning a Session.
func cleanupStart(home string, cancel context.CancelFunc) {
	if cancel != nil {
		cancel()
	}
	_ = os.RemoveAll(home)
}
