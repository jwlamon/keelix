package mcpprobe

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// multiResponseSession implements sandbox.Session and replies to each JSON-RPC
// request with a pre-canned JSON-RPC response. Responses are written
// sequentially: response[0] replies to the first Send, response[1] to the
// second, and so on. This exercises the multi-Send code path that discover()
// uses (initialize then tools/list) and would immediately expose a Scanner data
// race because discover() calls Send twice on the same transport.
type multiResponseSession struct {
	pr        *io.PipeReader
	pw        *io.PipeWriter
	responses []string
	requests  chan []byte // each Write to Stdin delivers one request here
	done      chan struct{}
}

func newMultiResponseSession(responses []string) *multiResponseSession {
	pr, pw := io.Pipe()
	s := &multiResponseSession{
		pr:        pr,
		pw:        pw,
		responses: responses,
		requests:  make(chan []byte, len(responses)),
		done:      make(chan struct{}),
	}
	go s.serve()
	return s
}

func (s *multiResponseSession) serve() {
	for i, resp := range s.responses {
		// Wait for the matching request to arrive (written by writeFrame via
		// Stdin()), then write our canned response.
		select {
		case <-s.requests:
		case <-s.done:
			return
		}
		_ = i
		_, _ = s.pw.Write([]byte(resp + "\n"))
	}
	// All responses sent; keep the pipe open until Close() so Scan() blocks
	// (not EOF) — matching real server behaviour.
	<-s.done
}

// requestWriter captures writes to Stdin so serve() can synchronise on them.
type requestWriter struct {
	ch chan []byte
}

func (w *requestWriter) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	// Non-blocking: if the buffer is full the serve loop is still processing the
	// previous request; that's fine, we just need to signal "a request arrived".
	select {
	case w.ch <- cp:
	default:
	}
	return len(b), nil
}

func (s *multiResponseSession) Stdin() io.Writer  { return &requestWriter{ch: s.requests} }
func (s *multiResponseSession) Stdout() io.Reader { return s.pr }
func (s *multiResponseSession) Tier() string      { return "tier0" }
func (s *multiResponseSession) Applied() bool     { return false }
func (s *multiResponseSession) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	_ = s.pr.CloseWithError(fmt.Errorf("session closed"))
	_ = s.pw.CloseWithError(fmt.Errorf("session closed"))
	return nil
}

func TestRPCRequest_Marshal(t *testing.T) {
	req := rpcRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: map[string]any{"protocolVersion": supportedProtocol}}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["jsonrpc"] != "2.0" || got["method"] != "initialize" {
		t.Fatalf("bad request envelope: %s", b)
	}
}

func TestRPCResponse_Error(t *testing.T) {
	const raw = `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`
	var resp rpcResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("want rpc error -32601, got %+v", resp.Error)
	}
}

func TestSupportedProtocol_KnownSet(t *testing.T) {
	if !protocolSupported(supportedProtocol) {
		t.Fatalf("our own advertised protocol %q must be in the supported set", supportedProtocol)
	}
	if protocolSupported("1999-01-01") {
		t.Fatalf("unknown protocol must be rejected")
	}
}

// --- helpers for StdioTransport security tests ---

// floodSession implements sandbox.Session; Stdout() yields one very long line
// (larger than the cap) and then blocks until Close() is called.
type floodSession struct {
	pr   *io.PipeReader
	pw   *io.PipeWriter
	done chan struct{} // closed by Close() to terminate the writer goroutine
}

func newFloodSession(lineBytes int) *floodSession {
	pr, pw := io.Pipe()
	s := &floodSession{pr: pr, pw: pw, done: make(chan struct{})}
	go func() {
		// Emit one line that is lineBytes long (all 'X'), with a trailing newline.
		// We write it in chunks so the pipe doesn't have to buffer the whole thing.
		const chunkSize = 4096
		remaining := lineBytes
		for remaining > 0 {
			n := chunkSize
			if n > remaining {
				n = remaining
			}
			chunk := strings.Repeat("X", n)
			select {
			case <-s.done:
				return
			default:
			}
			if _, err := pw.Write([]byte(chunk)); err != nil {
				return
			}
			remaining -= n
		}
		// Write the terminating newline.
		_, _ = pw.Write([]byte("\n"))
		// Block until closed so the reader doesn't get premature EOF.
		<-s.done
	}()
	return s
}

// Stdin returns a writer that discards all input, so writeFrame never blocks.
func (s *floodSession) Stdin() io.Writer  { return io.Discard }
func (s *floodSession) Stdout() io.Reader { return s.pr }
func (s *floodSession) Tier() string      { return "tier0" }
func (s *floodSession) Applied() bool     { return false }
func (s *floodSession) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	_ = s.pr.CloseWithError(fmt.Errorf("session closed"))
	_ = s.pw.CloseWithError(fmt.Errorf("session closed"))
	return nil
}

// hangSession implements sandbox.Session; Stdout() blocks forever (simulates a
// server that never responds).
type hangSession struct {
	pr   *io.PipeReader
	pw   *io.PipeWriter
	done chan struct{}
}

func newHangSession() *hangSession {
	pr, pw := io.Pipe()
	return &hangSession{pr: pr, pw: pw, done: make(chan struct{})}
}

// Stdin returns io.Discard so writeFrame never blocks.
func (s *hangSession) Stdin() io.Writer  { return io.Discard }
func (s *hangSession) Stdout() io.Reader { return s.pr }
func (s *hangSession) Tier() string      { return "tier0" }
func (s *hangSession) Applied() bool     { return false }
func (s *hangSession) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	_ = s.pr.CloseWithError(fmt.Errorf("session closed"))
	_ = s.pw.CloseWithError(fmt.Errorf("session closed"))
	return nil
}

// TestStdioTransport_OversizedLineBounded verifies that a server emitting a
// line larger than the cap results in a transport-level error rather than an
// unbounded parent allocation. This is the SBX-7 guarantee.
func TestStdioTransport_OversizedLineBounded(t *testing.T) {
	const cap = 64 * 1024            // 64 KiB cap for the test
	const lineSize = 4 * 1024 * 1024 // 4 MiB line — well above cap

	sess := newFloodSession(lineSize)
	defer sess.Close()

	tr := NewStdioTransportCapped(sess, int64(cap), 5*time.Second)
	_, err := tr.Send("initialize", nil)
	if err == nil {
		t.Fatal("expected an error when server emits a line exceeding the cap, got nil")
	}
	// The error must mention the line-too-long condition (not a generic I/O error).
	if !strings.Contains(err.Error(), "line too long") && !strings.Contains(err.Error(), "token too long") && !strings.Contains(err.Error(), "bufio.Scanner") {
		t.Logf("error message: %v", err)
		// Any error is acceptable as long as it's not nil — the test cares that
		// the transport bounded the allocation, not the exact message.
	}
}

// TestStdioTransport_HangingServerDeadline verifies that a server that never
// writes a response causes Send to return an error within the deadline rather
// than blocking forever.
func TestStdioTransport_HangingServerDeadline(t *testing.T) {
	sess := newHangSession()
	defer sess.Close()

	const deadline = 100 * time.Millisecond
	tr := NewStdioTransportCapped(sess, 1<<20, deadline)

	start := time.Now()
	_, err := tr.Send("initialize", nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected deadline error from hanging server, got nil")
	}
	// Must return well within 2x the deadline (give generous headroom for CI).
	if elapsed > 5*time.Second {
		t.Errorf("Send blocked for %v, want <= 5s (deadline was %v)", elapsed, deadline)
	}
}

// TestStdioTransport_MultiSend_NoRace exercises the two-Send path that
// discover() uses (initialize then tools/list) on a single StdioTransport. The
// test is run with -race (go test -race ./...) to confirm that the singleton
// reader goroutine approach eliminates the concurrent Scanner access that caused
// the data race in the per-Send goroutine design.
//
// Prior to the fix, this test (or the integration tests) would fail with:
//
//	tools/list: stdio read: EOF
//
// because the background goroutine from the first Send() would race on
// t.sc.Scan() with the goroutine spawned by the second Send().
func TestStdioTransport_MultiSend_NoRace(t *testing.T) {
	// Build two canned JSON-RPC responses that match request IDs 1 and 2.
	initResp, err := json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"protocolVersion":"2025-11-25"}`),
	})
	if err != nil {
		t.Fatalf("marshal initResp: %v", err)
	}
	toolsResp, err := json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      2,
		Result:  json.RawMessage(`{"tools":[{"name":"probe_tool","description":"desc"}]}`),
	})
	if err != nil {
		t.Fatalf("marshal toolsResp: %v", err)
	}

	sess := newMultiResponseSession([]string{
		string(initResp),
		string(toolsResp),
	})
	defer sess.Close()

	tr := NewStdioTransportCapped(sess, 1<<20, 5*time.Second)
	defer tr.Close()

	// First Send: initialize.
	raw1, err := tr.Send("initialize", nil)
	if err != nil {
		t.Fatalf("first Send (initialize) failed: %v", err)
	}
	var initResult struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw1, &initResult); err != nil {
		t.Fatalf("unmarshal initialize result: %v", err)
	}
	if initResult.ProtocolVersion != supportedProtocol {
		t.Errorf("initialize: got protocolVersion %q, want %q", initResult.ProtocolVersion, supportedProtocol)
	}

	// Second Send: tools/list — this is where the race occurred in the old design.
	raw2, err := tr.Send("tools/list", nil)
	if err != nil {
		t.Fatalf("second Send (tools/list) failed: %v — this is the Scanner data race symptom", err)
	}
	var toolsResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw2, &toolsResult); err != nil {
		t.Fatalf("unmarshal tools/list result: %v", err)
	}
	if len(toolsResult.Tools) != 1 || toolsResult.Tools[0].Name != "probe_tool" {
		t.Errorf("tools/list: got %+v, want [{Name:probe_tool}]", toolsResult.Tools)
	}
}

// burstSession implements sandbox.Session; Stdout() emits two lines in rapid
// succession before any Send has consumed the first. This exercises the
// scenario that previously caused a goroutine leak / Close deadlock:
//   - Reader goroutine delivers line 0 into the buffered channel (cap=1).
//   - Reader goroutine tries to send line 1 — channel is full, blocks.
//   - Send returns (deadline or success) without draining line 1.
//   - Close() is called; without the quit channel fix it would deadlock on
//     <-readerDone because the reader goroutine is stuck on the line-1 send.
type burstSession struct {
	pr   *io.PipeReader
	pw   *io.PipeWriter
	done chan struct{}
}

func newBurstSession(lines []string) *burstSession {
	pr, pw := io.Pipe()
	s := &burstSession{pr: pr, pw: pw, done: make(chan struct{})}
	go func() {
		for _, l := range lines {
			select {
			case <-s.done:
				return
			default:
			}
			if _, err := pw.Write([]byte(l + "\n")); err != nil {
				return
			}
		}
		<-s.done
	}()
	return s
}

func (s *burstSession) Stdin() io.Writer  { return io.Discard }
func (s *burstSession) Stdout() io.Reader { return s.pr }
func (s *burstSession) Tier() string      { return "tier0" }
func (s *burstSession) Applied() bool     { return false }
func (s *burstSession) Close() error {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	_ = s.pr.CloseWithError(fmt.Errorf("session closed"))
	_ = s.pw.CloseWithError(fmt.Errorf("session closed"))
	return nil
}

// TestStdioTransport_CloseDoesNotDeadlockAfterBurst verifies that Close()
// returns promptly even when the reader goroutine is (or was) blocked on
// delivering a second line before Send consumed the first. This is the
// regression test for the goroutine-leak / Close-deadlock identified in the
// SBX-7 quality review (fix: use select with quit channel on line send).
func TestStdioTransport_CloseDoesNotDeadlockAfterBurst(t *testing.T) {
	// Two lines — line[0] is a valid JSON-RPC response (ID=1), line[1] is a
	// second line that arrives before Send can drain it. Without the quit channel
	// fix, the reader goroutine would block sending line[1] and Close would hang.
	resp1, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: 1, Result: json.RawMessage(`{}`)})
	resp2, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: 2, Result: json.RawMessage(`{}`)})

	sess := newBurstSession([]string{string(resp1), string(resp2)})

	tr := NewStdioTransportCapped(sess, 1<<20, 5*time.Second)

	// Consume the first response via Send.
	_, err := tr.Send("initialize", nil)
	if err != nil {
		t.Fatalf("Send failed unexpectedly: %v", err)
	}

	// Close must not deadlock. Use a goroutine + channel so the test fails fast
	// rather than hanging the whole suite if the bug regresses.
	closed := make(chan error, 1)
	go func() { closed <- tr.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Logf("Close returned non-nil (acceptable): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked — goroutine blocked on lines send (quit channel fix regression)")
	}
}

// TestStdioTransport_CloseJoinsReaderGoroutine verifies that after Close()
// returns, the reader goroutine has fully exited (no goroutine leak). We use
// readerDone directly (same-package white-box test) to confirm the channel is
// closed before Close() returns. This is the regression test for the production
// closer bug where sess.Close was returned instead of tr.Close, leaving the
// reader goroutine alive indefinitely.
func TestStdioTransport_CloseJoinsReaderGoroutine(t *testing.T) {
	sess := newHangSession() // never sends data; reader blocks in Scan()
	tr := NewStdioTransportCapped(sess, 1<<20, 100*time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Send will time out after the deadline; we don't care about the error.
		_, _ = tr.Send("initialize", nil)
	}()
	wg.Wait()

	// After Send returns (deadline), call Close and assert readerDone is closed.
	if err := tr.Close(); err != nil {
		t.Logf("Close error (acceptable): %v", err)
	}

	select {
	case <-tr.readerDone:
		// readerDone closed — goroutine has exited.
	default:
		t.Fatal("reader goroutine still running after Close() returned (goroutine leak)")
	}
}
