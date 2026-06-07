package mcpprobe

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_InitializeAndList(t *testing.T) {
	srv := newFakeServer(
		fakeTool{"read_file", "Reads a file."},
		fakeTool{"write_file", "Writes a file."},
	)
	c := newClient(srv.transport())
	tools, err := c.discover()
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if !srv.gotInit || !srv.gotNotify || !srv.gotList {
		t.Fatalf("handshake incomplete: init=%v notify=%v list=%v", srv.gotInit, srv.gotNotify, srv.gotList)
	}
	if len(tools) != 2 || tools[0].Name != "read_file" || tools[1].Name != "write_file" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
	if tools[0].Description != "Reads a file." {
		t.Fatalf("description not captured: %q", tools[0].Description)
	}
}

func TestClient_UnsupportedProtocolAborts(t *testing.T) {
	srv := newFakeServer(fakeTool{"x", "y"})
	srv.protocol = "1999-01-01" // not in the supported set
	c := newClient(srv.transport())
	if _, err := c.discover(); err == nil {
		t.Fatalf("want abort on unsupported protocolVersion, got nil error")
	}
	if srv.gotList {
		t.Fatalf("must NOT call tools/list after protocol mismatch")
	}
}

func TestClient_Pagination(t *testing.T) {
	srv := newFakeServer(
		fakeTool{"a", "da"}, fakeTool{"b", "db"}, fakeTool{"c", "dc"}, fakeTool{"d", "dd"}, fakeTool{"e", "de"},
	)
	srv.pageSize = 2
	c := newClient(srv.transport())
	tools, err := c.discover()
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(tools) != 5 {
		t.Fatalf("pagination lost tools: got %d want 5", len(tools))
	}
	if tools[4].Name != "e" {
		t.Fatalf("last page wrong: %+v", tools[4])
	}
}

func TestClient_OverHTTPTransport(t *testing.T) {
	srv := newFakeServer(fakeTool{"ping", "Pong."})
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c := newClient(NewHTTPTransport(ts.URL, 5*time.Second))
	tools, err := c.discover()
	if err != nil {
		t.Fatalf("discover over http: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "ping" {
		t.Fatalf("unexpected http tools: %+v", tools)
	}
}
