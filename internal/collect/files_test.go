package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStatFilesFixture(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(secret, []byte(`{"icc":false}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	missing := filepath.Join(dir, "absent.conf")

	facts := statFiles([]string{secret, missing})
	if len(facts) != 2 {
		t.Fatalf("statFiles returned %d facts, want 2", len(facts))
	}

	byPath := map[string]FileFactView{}
	for _, f := range facts {
		byPath[f.Path] = FileFactView{Exists: f.Exists, Mode: f.Mode, Size: f.Size}
	}

	if v := byPath[secret]; !v.Exists {
		t.Errorf("%s: Exists = false, want true", secret)
	} else if v.Mode != "0600" {
		t.Errorf("%s: Mode = %q, want %q", secret, v.Mode, "0600")
	} else if v.Size != int64(len(`{"icc":false}`)) {
		t.Errorf("%s: Size = %d, want %d", secret, v.Size, len(`{"icc":false}`))
	}

	if v := byPath[missing]; v.Exists {
		t.Errorf("%s: Exists = true, want false", missing)
	}
}

// FileFactView is a test-local projection to keep assertions terse.
type FileFactView struct {
	Exists bool
	Mode   string
	Size   int64
}
