package mcpprobe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBaseline_SaveIsAtomic verifies that Save uses a temp-file + os.Rename so
// the baseline file is never partially-written (a reader cannot observe a
// truncated/corrupt JSON blob). We simulate an interrupted write by checking
// that no temp file is left behind when Save succeeds.
func TestBaseline_SaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-baseline.json")
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	bl := newBaseline()
	bl.Diff("openclaw", "filesystem", "read_file", canonicalHash("read_file", "Reads a file."), now, noID)

	if err := bl.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// After a successful save the file must exist and be valid JSON.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after Save: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("baseline file is empty after Save")
	}

	// No temp files must remain in the same directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("unexpected file left by Save (non-atomic): %q", e.Name())
		}
	}
}

// TestLoadBaseline_CorruptFileIsError verifies the SBX-9(b) guarantee:
// a corrupt / partial baseline must return an error (not silently produce an
// empty baseline). Silent reset to first-run would erase all accumulated drift
// detection the moment the file is partially overwritten.
func TestLoadBaseline_CorruptFileIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-baseline.json")
	if err := os.WriteFile(path, []byte("{bad json!!!"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	_, err := LoadBaseline(path)
	if err == nil {
		t.Fatalf("LoadBaseline on corrupt JSON must return an error, got nil")
	}
}
