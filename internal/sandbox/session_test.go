package sandbox

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// TestBaseRunnerStartRoundTrip starts a /bin/cat child via the streaming API,
// writes a line to Stdin, and reads it back from Stdout — the exact shape the
// SLD stdio MCP transport drives.
func TestBaseRunnerStartRoundTrip(t *testing.T) {
	r := &baseRunner{}
	sess, err := r.Start(context.Background(), Spec{
		Command: "/bin/cat",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Close()

	if sess.Tier() != "tier0" {
		t.Errorf("Tier() = %q, want tier0", sess.Tier())
	}

	if _, err := io.WriteString(sess.Stdin(), "ping\n"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	line, err := bufio.NewReader(sess.Stdout()).ReadString('\n')
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if strings.TrimSpace(line) != "ping" {
		t.Errorf("round-trip = %q, want ping", strings.TrimSpace(line))
	}
}

// TestSessionCloseStopsChild asserts Close terminates the child so a second
// read returns EOF rather than hanging.
func TestSessionCloseStopsChild(t *testing.T) {
	r := &baseRunner{}
	sess, err := r.Start(context.Background(), Spec{
		Command: "/bin/cat",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	out := sess.Stdout()
	if err := sess.Close(); err != nil {
		// cat is killed via signal, so Close may surface a non-nil wait error;
		// that is acceptable — we only require the child to actually stop.
		t.Logf("Close returned (expected on signal kill): %v", err)
	}
	// After Close the stdout pipe must reach EOF, not block forever.
	done := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(out)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stdout did not reach EOF after Close — child still running")
	}
}

// TestBaseSession_AppliedDefaultsFalse asserts that a baseSession started via
// the Tier-0 baseRunner reports Applied()==false (no kernel confinement).
func TestBaseSession_AppliedDefaultsFalse(t *testing.T) {
	r := &baseRunner{}
	sess, err := r.Start(context.Background(), Spec{
		Command: "/bin/cat",
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Close()

	if sess.Applied() {
		t.Error("baseRunner.Start: Applied() = true, want false (no kernel confinement for Tier-0)")
	}
}

// assert *baseRunner satisfies Runner (Run+Start) and *baseSession satisfies
// Session at compile time.
var (
	_ Runner  = (*baseRunner)(nil)
	_ Session = (*baseSession)(nil)
)
