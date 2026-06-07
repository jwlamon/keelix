package mcpprobe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/jwlamon/keelix/internal/sandbox"
)

// fakeTool is one advertised tool in the fake server.
type fakeTool struct {
	name string
	desc string
}

// fakeServer is an in-process MCP server used by tests. It records what it was
// asked, validates the handshake, and answers initialize / tools/list with the
// configured tools. protocol is what it returns in initialize (set to an
// unsupported value to exercise the abort path).
type fakeServer struct {
	protocol  string
	tools     []fakeTool
	pageSize  int // 0 = single page
	gotInit   bool
	gotNotify bool
	gotList   bool
}

func newFakeServer(tools ...fakeTool) *fakeServer {
	return &fakeServer{protocol: supportedProtocol, tools: tools}
}

// handle answers one JSON-RPC method, returning the result payload to embed.
func (f *fakeServer) handle(method string, params json.RawMessage, cursor string) (any, *rpcError) {
	switch method {
	case "initialize":
		f.gotInit = true
		return map[string]any{
			"protocolVersion": f.protocol,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fake", "version": "0.0.0"},
		}, nil
	case "tools/list":
		f.gotList = true
		start := 0
		if cursor != "" {
			// cursor is the index of the next page as a string.
			for i := 0; i < len(cursor); i++ {
				if cursor[i] < '0' || cursor[i] > '9' {
					return nil, &rpcError{Code: -32602, Message: "bad cursor"}
				}
			}
			start = atoiTest(cursor)
		}
		end := len(f.tools)
		next := ""
		if f.pageSize > 0 && start+f.pageSize < len(f.tools) {
			end = start + f.pageSize
			next = itoa(end)
		}
		var list []map[string]any
		for _, tl := range f.tools[start:end] {
			list = append(list, map[string]any{"name": tl.name, "description": tl.desc})
		}
		out := map[string]any{"tools": list}
		if next != "" {
			out["nextCursor"] = next
		}
		return out, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found"}
	}
}

// --- fakeServer as a direct Transport (no process, no sandbox) ---

type fakeTransport struct {
	srv *fakeServer
	id  int
}

func (f *fakeServer) transport() *fakeTransport { return &fakeTransport{srv: f} }

func (t *fakeTransport) Send(method string, params any) (json.RawMessage, error) {
	t.id++
	var pr json.RawMessage
	if params != nil {
		pr, _ = json.Marshal(params)
	}
	cursor := ""
	if method == "tools/list" {
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(pr, &p)
		cursor = p.Cursor
	}
	res, rerr := t.srv.handle(method, pr, cursor)
	if rerr != nil {
		return nil, rerr
	}
	return json.Marshal(res)
}

func (t *fakeTransport) notify(method string, params any) error {
	if method == "notifications/initialized" {
		t.srv.gotNotify = true
	}
	return nil
}

func (t *fakeTransport) Close() error { return nil }

// --- fakeServer as an http.Handler for HTTPTransport tests ---

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(body, &req)
	cursor := ""
	if req.Method == "tools/list" {
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(req.Params, &p)
		cursor = p.Cursor
	}
	if req.ID == 0 {
		// notification (no id) — record and ack.
		if req.Method == "notifications/initialized" {
			f.gotNotify = true
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	res, rerr := f.handle(req.Method, req.Params, cursor)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if rerr != nil {
		_ = enc.Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rerr})
		return
	}
	raw, _ := json.Marshal(res)
	_ = enc.Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: raw})
}

func atoiTest(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// --- fakeRunner: a sandbox.Runner whose Session is driven by a fakeServer ---

// fakeSession bridges a fakeServer to the sandbox.Session contract used by the
// stdio path. Stdin/Stdout are unused here because we shortcut the wire: the
// fakeSessionTransport (below) talks to the fakeServer directly. We still need
// Stdin()/Stdout() to satisfy the interface, so they return no-op pipes.
type fakeSession struct {
	srv     *fakeServer
	tier    string
	applied bool
	r       *io.PipeReader
	w       *io.PipeWriter
}

func (s *fakeSession) Stdin() io.Writer  { return s.w }
func (s *fakeSession) Stdout() io.Reader { return s.r }
func (s *fakeSession) Tier() string      { return s.tier }
func (s *fakeSession) Applied() bool     { return s.applied }
func (s *fakeSession) Close() error {
	_ = s.w.Close()
	return s.r.Close()
}

// pipePair returns a connected pipe for fakeSession's no-op stdio.
func pipePair() (*io.PipeReader, *io.PipeWriter) { return io.Pipe() }

// setStdioClientSeam replaces newStdioClient with one that talks to the
// fakeServer behind the runner's session DIRECTLY (no real child, no real
// wire), exercising Probe's orchestration deterministically. It restores the
// original on cleanup. Requires the runner to be a *fakeRunner.
func setStdioClientSeam(t *testing.T) func() {
	t.Helper()
	orig := newStdioClient
	newStdioClient = func(ctx context.Context, r sandbox.Runner, spec ServerSpec) (*MCPClient, string, bool, func() error, error) {
		fr, ok := r.(*fakeRunner)
		if !ok {
			return orig(ctx, r, spec)
		}
		srv := fr.servers[spec.Command]
		if srv == nil {
			srv = newFakeServer()
		}
		// Honest tier: demote to tier0 when not applied, matching real probe logic.
		tier := fr.tier
		if !fr.applied {
			tier = "tier0"
		}
		return newClient(srv.transport()), tier, fr.applied, func() error { return nil }, nil
	}
	return func() { newStdioClient = orig }
}
