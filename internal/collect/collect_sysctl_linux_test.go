//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectSysctlFromDir(t *testing.T) {
	base := t.TempDir()
	writes := map[string]string{
		"kernel/randomize_va_space": "2\n",
		"kernel/kptr_restrict":      "1\n",
		"kernel/dmesg_restrict":     "1\n",
		"kernel/yama/ptrace_scope":  "1\n",
		"fs/suid_dumpable":          "0\n",
	}
	for rel, val := range writes {
		fullPath := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
		}
		if err := os.WriteFile(fullPath, []byte(val), 0o644); err != nil {
			t.Fatalf("write %s: %v", fullPath, err)
		}
	}

	fact := collectSysctlFromDir(base)
	if !fact.SchemaKnown {
		t.Fatal("SchemaKnown=false, want true")
	}
	if fact.SchemaID != "sysctl" {
		t.Errorf("SchemaID=%q, want sysctl", fact.SchemaID)
	}
	wantKeys := []string{
		"kernel.randomize_va_space",
		"kernel.kptr_restrict",
		"kernel.dmesg_restrict",
		"kernel.yama.ptrace_scope",
		"fs.suid_dumpable",
	}
	for _, k := range wantKeys {
		if _, ok := fact.Values[k]; !ok {
			t.Errorf("missing key %q in sysctl fact", k)
		}
	}
	if fact.Values["kernel.randomize_va_space"] != "2" {
		t.Errorf("kernel.randomize_va_space=%q, want 2", fact.Values["kernel.randomize_va_space"])
	}
	if fact.Values["fs.suid_dumpable"] != "0" {
		t.Errorf("fs.suid_dumpable=%q, want 0", fact.Values["fs.suid_dumpable"])
	}
}

func TestCollectSysctl_MissingProcEntry(t *testing.T) {
	// A dir that exists but has none of the sysctl files → SchemaKnown=false.
	base := t.TempDir()
	fact := collectSysctlFromDir(base)
	if fact.SchemaKnown {
		t.Error("empty dir: want SchemaKnown=false, got true")
	}
}
