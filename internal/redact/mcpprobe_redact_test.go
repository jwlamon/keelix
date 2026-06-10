package redact

import (
	"strings"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// TestResultRedactsMCPProbe verifies that redact.Result scrubs every free-text
// field in Collector.MCPProbe — server names, tool names, and error strings —
// so that a malicious tool name / description fragment carrying a secret cannot
// escape into the report. This is the SBX-9(a) security guarantee.
func TestResultRedactsMCPProbe(t *testing.T) {
	// Plant a high-entropy token as a tool name (simulates a malicious server
	// naming its tool after a secret so the tool name carries the secret out).
	token := "Zx9Q2pL7mWvD3hKt8RnBuF1cYa6Es4Jg" // 32 chars, high Shannon entropy

	r := &model.Result{
		Collector: &model.Signals{
			MCPProbe: &model.MCPProbe{
				Servers: []model.MCPServerProbe{
					{
						Client:    "openclaw",
						Name:      "evil-server",
						Transport: "stdio",
						Reached:   true,
						Errors:    []string{"connection error: token=" + token},
						Tools: []model.MCPToolFact{
							{
								Name:     token,
								DescHash: "abc123",
							},
							{
								Name:     "safe_tool",
								DescHash: "def456",
							},
						},
					},
				},
			},
		},
	}

	Result(r)

	srv := r.Collector.MCPProbe.Servers[0]

	// Errors must be scrubbed.
	for i, e := range srv.Errors {
		if strings.Contains(e, token) {
			t.Errorf("MCPProbe.Servers[0].Errors[%d] leaked token: %q", i, e)
		}
		if !strings.Contains(e, marker) {
			t.Errorf("MCPProbe.Servers[0].Errors[%d] not redacted: %q", i, e)
		}
	}

	// Tool name containing the token must be redacted.
	tool0 := srv.Tools[0]
	if strings.Contains(tool0.Name, token) {
		t.Errorf("MCPProbe.Tools[0].Name leaked token: %q", tool0.Name)
	}
	if !strings.Contains(tool0.Name, marker) {
		t.Errorf("MCPProbe.Tools[0].Name not redacted: %q", tool0.Name)
	}

	// Safe tool name must be preserved.
	tool1 := srv.Tools[1]
	if tool1.Name != "safe_tool" {
		t.Errorf("MCPProbe.Tools[1].Name modified unexpectedly: %q", tool1.Name)
	}
}
