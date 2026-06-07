package model_test

import (
	"encoding/json"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestMCPProbeZeroValueIsNilOnSignals(t *testing.T) {
	// The field is omitempty and pointer; a fresh Signals must round-trip with
	// mcp_probe absent from JSON.
	s := model.Signals{Version: "1.0.0"}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["mcp_probe"]; ok {
		t.Error("mcp_probe must be absent when nil (omitempty)")
	}
}

func TestMCPProbeRoundTrip(t *testing.T) {
	probe := &model.MCPProbe{
		Servers: []model.MCPServerProbe{
			{
				Client:      "claude-desktop",
				Name:        "my-server",
				Transport:   "stdio",
				Reached:     true,
				SandboxTier: "none",
				Tools: []model.MCPToolFact{
					{Name: "bash", DescHash: "abc123", Drifted: false, FirstSeen: true},
				},
				Errors: []string{"timeout on tool list"},
			},
		},
	}
	s := model.Signals{Version: "1.0.0", MCPProbe: probe}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var s2 model.Signals
	if err := json.Unmarshal(b, &s2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s2.MCPProbe == nil {
		t.Fatal("MCPProbe is nil after round-trip")
	}
	if len(s2.MCPProbe.Servers) != 1 {
		t.Fatalf("Servers len = %d, want 1", len(s2.MCPProbe.Servers))
	}
	srv := s2.MCPProbe.Servers[0]
	if srv.Name != "my-server" {
		t.Errorf("Name = %q, want %q", srv.Name, "my-server")
	}
	if srv.Transport != "stdio" {
		t.Errorf("Transport = %q, want %q", srv.Transport, "stdio")
	}
	if !srv.Reached {
		t.Error("Reached = false, want true")
	}
	if srv.SandboxTier != "none" {
		t.Errorf("SandboxTier = %q, want %q", srv.SandboxTier, "none")
	}
	if len(srv.Tools) != 1 || srv.Tools[0].Name != "bash" {
		t.Errorf("Tools = %+v, want [{bash ...}]", srv.Tools)
	}
	if len(srv.Errors) != 1 {
		t.Errorf("Errors len = %d, want 1", len(srv.Errors))
	}
}
