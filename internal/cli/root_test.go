package cli

import (
	"strings"
	"testing"
)

func TestRootCommandIsKeelix(t *testing.T) {
	root := newRootCmd()
	if root.Use != "keelix" {
		t.Fatalf("root.Use = %q, want %q", root.Use, "keelix")
	}
}

func TestVersionLineSaysKeelix(t *testing.T) {
	// The `version` subcommand prints "keelix <ver>\n..." — lock the brand token.
	cmd := newVersionCmd()
	var buf strings.Builder
	cmd.SetOut(&buf)
	cmd.Run(cmd, nil)
	if !strings.HasPrefix(buf.String(), "keelix ") {
		t.Fatalf("version output = %q, want prefix %q", buf.String(), "keelix ")
	}
}

func TestRegradeCommandIsRegistered(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "regrade" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("regrade subcommand not registered on root")
	}
}
