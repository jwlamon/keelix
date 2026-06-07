package cli

import "testing"

func TestNewSandboxChildCmd_HiddenAndNamed(t *testing.T) {
	cmd := newSandboxChildCmd()
	if cmd.Use != "__mcp-sandbox-child" {
		t.Fatalf("Use=%q", cmd.Use)
	}
	if !cmd.Hidden {
		t.Fatalf("expected the sandbox child command to be Hidden")
	}
	if cmd.Run == nil {
		t.Fatalf("expected a Run function")
	}
}

func TestRootRegistersSandboxChild(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "__mcp-sandbox-child" {
			found = true
		}
	}
	if !found {
		t.Fatalf("root must register the hidden __mcp-sandbox-child command")
	}
}
