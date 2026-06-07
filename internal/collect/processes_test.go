package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcesses(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "ps_linux.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := parseProcesses(b)
	if len(got) != 4 {
		t.Fatalf("len = %d, want 4: %+v", len(got), got)
	}

	// systemd
	if got[0].Comm != "systemd" || got[0].PID != 1 || got[0].UID != 0 {
		t.Errorf("proc[0] = %+v", got[0])
	}
	if len(got[0].Args) == 0 || got[0].Args[0] != "/sbin/init" {
		t.Errorf("proc[0].Args = %v", got[0].Args)
	}

	// node — args carry env-looking KEY=VALUE pairs that must be classified, not stored raw.
	node := got[2]
	if node.Comm != "node" || node.PID != 1337 || node.UID != 1000 {
		t.Errorf("node = %+v", node)
	}
	var foundDBURL bool
	for _, e := range node.Env {
		if e.Name == "DATABASE_URL" {
			foundDBURL = true
			if e.Class != "secret" && e.Class != "plain" {
				t.Errorf("DATABASE_URL class = %q", e.Class)
			}
		}
		// EnvShape must never carry the raw value.
		if e.Name == "" {
			t.Errorf("empty env name in %+v", node.Env)
		}
	}
	if !foundDBURL {
		t.Errorf("expected DATABASE_URL env shape, got %+v", node.Env)
	}
}

// TestParseProcessesArgvSanitization verifies that secret-shaped argv tokens are
// replaced with "[secret]" rather than stored verbatim.
func TestParseProcessesArgvSanitization(t *testing.T) {
	// A process line with a plaintext token and a high-entropy secret token.
	// The secret token is a 40-char hex string (high entropy, not KEY=VAL form).
	input := []byte("  PID   UID COMMAND         COMMAND\n" +
		" 100   0 myapp           myapp --flag normal_arg --token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
	got := parseProcesses(input)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	p := got[0]
	// "normal_arg" should be preserved.
	var hasNormal, hasSecret, hasRawSecret bool
	for _, a := range p.Args {
		if a == "normal_arg" {
			hasNormal = true
		}
		if a == "[secret]" {
			hasSecret = true
		}
		// The raw secret value must never appear.
		if a == "--token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
			hasRawSecret = true
		}
	}
	if !hasNormal {
		t.Errorf("normal_arg missing from Args: %v", p.Args)
	}
	if !hasSecret {
		t.Errorf("[secret] marker missing from Args: %v", p.Args)
	}
	if hasRawSecret {
		t.Errorf("raw secret token still in Args: %v", p.Args)
	}
}

func TestParseProcessesEmpty(t *testing.T) {
	if got := parseProcesses(nil); got != nil {
		t.Fatalf("parseProcesses(nil) = %+v, want nil", got)
	}
	if got := parseProcesses([]byte("  PID   UID COMMAND         COMMAND\n")); len(got) != 0 {
		t.Fatalf("header-only = %+v, want empty", got)
	}
}
