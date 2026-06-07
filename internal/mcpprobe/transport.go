package mcpprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jwlamon/keelix/internal/sandbox"
)

// supportedProtocol is the MCP protocol version keelix advertises in
// initialize. The server's returned protocolVersion is validated against
// protocols below; an unsupported value aborts that one server (we never
// blindly adopt whatever the server claims).
const supportedProtocol = "2025-11-25"

// protocols is the known-supported set we accept from a server's initialize
// result. Keep this conservative — these are wire contracts we have verified.
var protocols = map[string]struct{}{
	"2025-11-25": {},
	"2025-06-18": {},
	"2025-03-26": {},
	"2024-11-05": {},
}

func protocolSupported(v string) bool {
	_, ok := protocols[v]
	return ok
}

// rpcRequest is a JSON-RPC 2.0 request envelope.
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// rpcNotification is a JSON-RPC 2.0 notification (no id, no response expected).
type rpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// rpcError is the JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// rpcResponse is a JSON-RPC 2.0 response envelope.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Transport is one bidirectional MCP channel. Send issues a request and blocks
// for its matching response; notify fires a JSON-RPC notification (no reply).
type Transport interface {
	Send(method string, params any) (json.RawMessage, error)
	notify(method string, params any) error
	Close() error
}

// defaultLineCap is the per-line cap used by NewStdioTransport when no
// explicit cap is provided. Matches the sandbox.defaultOutputCap (1 MiB).
const defaultLineCap int64 = 1 << 20

// defaultCallDeadline is the per-Send deadline used by NewStdioTransport when
// no explicit deadline is provided.
const defaultCallDeadline = 20 * time.Second

// --- StdioTransport: JSON-RPC over a sandboxed child's stdin/stdout ---

// StdioTransport drives a sandbox.Session (from Runner.Start) speaking
// newline-delimited JSON-RPC over the child's Stdin/Stdout. The child is
// untrusted code, so it only ever runs inside the sandbox the Session wraps.
//
// lineCap bounds the maximum bytes the transport will buffer for a single
// newline-delimited frame. A line exceeding this cap is treated as an error
// for that server (the transport returns an error from Send); the parent
// process never allocates more than lineCap bytes for a single read.
//
// callDeadline is applied per Send call: if no matching response arrives
// within the deadline the session is closed and Send returns an error.
//
// A single background goroutine owns the bufio.Scanner exclusively. All Send
// calls receive lines through the shared lines channel; this eliminates the
// data race that occurs when multiple goroutines call Scan() concurrently.
type StdioTransport struct {
	sess         sandbox.Session
	id           int
	lineCap      int64
	callDeadline time.Duration

	// lines is the shared output of the singleton reader goroutine. It is
	// unbuffered so that Send receives lines in FIFO order with no extra
	// allocation. The goroutine is started by NewStdioTransportCapped and runs
	// until the underlying io.Reader signals EOF or an error (which happens when
	// sess.Close() is called).
	lines chan scanResult

	// quit is closed by Close() to signal the reader goroutine to stop. This is
	// separate from readerDone (which is closed BY the goroutine) to avoid a
	// chicken-and-egg deadlock: the goroutine cannot read from readerDone to
	// know it should quit, since it is the one that closes it.
	quit chan struct{}

	// readerDone is closed by the reader goroutine when it terminates, allowing
	// Close to drain and join cleanly.
	readerDone chan struct{}
}

// NewStdioTransport wraps a started sandbox.Session using the default 1 MiB
// line cap and 20 s call deadline.
func NewStdioTransport(sess sandbox.Session) *StdioTransport {
	return NewStdioTransportCapped(sess, defaultLineCap, defaultCallDeadline)
}

// NewStdioTransportCapped wraps a started sandbox.Session with an explicit
// per-line cap (bytes) and per-call deadline. lineCap must be > 0.
func NewStdioTransportCapped(sess sandbox.Session, lineCap int64, callDeadline time.Duration) *StdioTransport {
	if lineCap <= 0 {
		lineCap = defaultLineCap
	}
	sc := bufio.NewScanner(sess.Stdout())
	// bufio.Scanner's default token buffer is 4096 B; override it so that the
	// max is exactly lineCap. Allocate a small initial slice; the Scanner
	// grows it on demand up to lineCap.
	sc.Buffer(make([]byte, 4096), int(lineCap))

	t := &StdioTransport{
		sess:         sess,
		lineCap:      lineCap,
		callDeadline: callDeadline,
		// Buffer 1 so the reader goroutine can always deliver one result even if
		// Send has already returned (e.g. on deadline). Without a buffer the
		// goroutine could block forever waiting for a receiver that is gone.
		lines:      make(chan scanResult, 1),
		quit:       make(chan struct{}),
		readerDone: make(chan struct{}),
	}

	// Start the singleton Scanner goroutine. It owns sc exclusively; no other
	// goroutine ever calls sc.Scan().
	go func() {
		defer close(t.readerDone)
		for sc.Scan() {
			b := make([]byte, len(sc.Bytes()))
			copy(b, sc.Bytes())
			// Use a select so that Close() can unblock this goroutine even if no
			// consumer is waiting on t.lines. Without this, a second line arriving
			// before Send drains the first would block here permanently, and
			// Close()'s <-t.readerDone would deadlock.
			select {
			case t.lines <- scanResult{line: b}:
			case <-t.quit:
				return
			}
		}
		// Scan() returned false: deliver the terminal error (or EOF) once.
		err := sc.Err()
		if err == nil {
			err = io.EOF
		}
		// Non-blocking send: if the channel is full (buffered 1 and already has a
		// result) the consumer will drain it and eventually read this terminal
		// result. We must not block here because no goroutine is guaranteed to be
		// receiving — the transport may already be closing.
		select {
		case t.lines <- scanResult{err: err}:
		default:
			// A result is already queued. The consumer will drain it before calling
			// Scan again, but this goroutine is done anyway — just exit.
		}
	}()

	return t
}

// scanResult is the outcome of one bufio.Scanner.Scan() call shipped over the
// shared lines channel from the singleton reader goroutine.
type scanResult struct {
	line []byte
	err  error // non-nil when Scan() returned false; wraps sc.Err() or EOF
}

func (t *StdioTransport) Send(method string, params any) (json.RawMessage, error) {
	t.id++
	req := rpcRequest{JSONRPC: "2.0", ID: t.id, Method: method, Params: params}
	if err := t.writeFrame(req); err != nil {
		return nil, err
	}

	// Enforce a per-call deadline. We select over the shared lines channel and a
	// timer. When the deadline fires we close the session, which causes the
	// underlying io.Reader to return an error and unblocks the singleton reader
	// goroutine (which will then deliver a scanResult with err != nil).
	timer := time.NewTimer(t.callDeadline)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			// Deadline: close the session to unblock the reader goroutine, then
			// return a bounded error.
			_ = t.sess.Close()
			return nil, fmt.Errorf("stdio deadline exceeded after %v waiting for %q response", t.callDeadline, method)

		case sr := <-t.lines:
			if sr.err != nil {
				return nil, fmt.Errorf("stdio read: %w", sr.err)
			}
			line := bytes.TrimSpace(sr.line)
			if len(line) == 0 {
				continue
			}
			var resp rpcResponse
			if jerr := json.Unmarshal(line, &resp); jerr != nil {
				// Not a JSON-RPC response (e.g. a server log line on stdout); skip.
				continue
			}
			if resp.ID != t.id {
				continue // a notification or a stale id; keep reading
			}
			if resp.Error != nil {
				return nil, resp.Error
			}
			return resp.Result, nil
		}
	}
}

func (t *StdioTransport) notify(method string, params any) error {
	return t.writeFrame(rpcNotification{JSONRPC: "2.0", Method: method, Params: params})
}

func (t *StdioTransport) writeFrame(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := t.sess.Stdin().Write(b); err != nil {
		return fmt.Errorf("stdio write: %w", err)
	}
	return nil
}

func (t *StdioTransport) Close() error {
	// Signal the reader goroutine to stop before closing the session. This
	// prevents a deadlock: if the goroutine is blocked on the lines send (because
	// the channel is full and no consumer is draining it), closing the session
	// alone won't unblock it — only closing quit will.
	select {
	case <-t.quit:
		// already closed (idempotent)
	default:
		close(t.quit)
	}
	err := t.sess.Close()
	// Wait for the singleton reader goroutine to exit so that callers can be
	// sure there are no lingering goroutines after Close returns.
	<-t.readerDone
	return err
}

// --- HTTPTransport: single-POST streamable-HTTP (no SSE reconnect) ---

// HTTPTransport speaks JSON-RPC to a streamable-HTTP MCP server with one POST
// per call (application/json). We do not open an SSE stream or reconnect — a
// one-shot tools/list does not need it.
type HTTPTransport struct {
	url    string
	client *http.Client
	id     int
}

// NewHTTPTransport targets the given server URL with a bounded HTTP client.
func NewHTTPTransport(url string, timeout time.Duration) *HTTPTransport {
	return &HTTPTransport{url: url, client: &http.Client{Timeout: timeout}}
}

func (t *HTTPTransport) Send(method string, params any) (json.RawMessage, error) {
	t.id++
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: t.id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	resp, err := t.post(body)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

func (t *HTTPTransport) notify(method string, params any) error {
	body, err := json.Marshal(rpcNotification{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	hr, err := t.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(hr.Body, 1<<20))
	return hr.Body.Close()
}

func (t *HTTPTransport) post(body []byte) (*rpcResponse, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, t.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	hr, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer hr.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(hr.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if hr.StatusCode/100 != 2 {
		return nil, fmt.Errorf("http %d from %s", hr.StatusCode, t.url)
	}
	ct := hr.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		// A server that insists on SSE: extract the first data: JSON line.
		if line := firstSSEData(raw); line != nil {
			raw = line
		}
	}
	var resp rpcResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("http decode: %w", err)
	}
	return &resp, nil
}

// firstSSEData returns the JSON payload of the first "data:" line in an SSE
// body, or nil. We do not stream — just enough to read a single response.
func firstSSEData(b []byte) []byte {
	for _, ln := range bytes.Split(b, []byte("\n")) {
		ln = bytes.TrimSpace(ln)
		if bytes.HasPrefix(ln, []byte("data:")) {
			return bytes.TrimSpace(ln[len("data:"):])
		}
	}
	return nil
}

func (t *HTTPTransport) Close() error { return nil }

// itoa is a tiny helper kept local to avoid pulling strconv into call sites.
func itoa(i int) string { return strconv.Itoa(i) }
