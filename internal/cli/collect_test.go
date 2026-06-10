package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestCollectCmd_writesSignalsJSON(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "signals.json")

	cmd := newCollectCmd()
	cmd.SetArgs([]string{"-o", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("collect command failed: %v", err)
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading collect output: %v", err)
	}
	var sig model.Signals
	if err := json.Unmarshal(b, &sig); err != nil {
		t.Fatalf("collect output is not valid Signals JSON: %v\n%s", err, string(b))
	}
	if sig.Version != model.SignalsVersion {
		t.Errorf("Signals.Version = %q, want %q", sig.Version, model.SignalsVersion)
	}
}

func TestCollectCmd_registeredOnRoot(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Use == "collect" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("collect subcommand not registered on root")
	}
}

func TestScanFlags_collectWiring(t *testing.T) {
	dir := t.TempDir()
	compose := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatalf("writing compose fixture: %v", err)
	}
	sf := scanFlags{compose: compose}
	sf.collect = true
	sf.collectPrivileged = true
	sf.signals = "/tmp/signals.json"

	in, err := sf.input()
	if err != nil {
		t.Fatalf("input() error: %v", err)
	}
	if !in.Collect {
		t.Errorf("Input.Collect = false, want true")
	}
	if !in.CollectPrivileged {
		t.Errorf("Input.CollectPrivileged = false, want true")
	}
	if in.SignalsPath != "/tmp/signals.json" {
		t.Errorf("Input.SignalsPath = %q, want %q", in.SignalsPath, "/tmp/signals.json")
	}
	// Also verify the flags propagate into the Options struct that the engine
	// actually dispatches on (engine.Scan uses in.Options.Collect et al).
	if !in.Options.Collect {
		t.Errorf("Options.Collect = false, want true")
	}
	if !in.Options.CollectPrivileged {
		t.Errorf("Options.CollectPrivileged = false, want true")
	}
	if in.Options.SignalsPath != "/tmp/signals.json" {
		t.Errorf("Options.SignalsPath = %q, want %q", in.Options.SignalsPath, "/tmp/signals.json")
	}
}

func TestScanCmd_hasCollectFlags(t *testing.T) {
	cmd := newScanCmd()
	for _, name := range []string{"collect", "collect-privileged", "signals"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("scan command missing --%s flag", name)
		}
	}
}
