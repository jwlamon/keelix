package collect

// TestRFX5_AGT005_AGT010_SubtreeWalk is the PARSER-FED regression test for RFX-5.
// It exercises the complete collect.Collect pipeline against a controlled temp
// HOME directory and verifies that:
//
//   (a) AGT005 fires when a .claude.json.bak backup file is present.
//   (b) AGT010 fires when a .claude/skills/<name>/.git/config is present.
//
// Both checks were DEAD before this fix because:
//   - The allowlist had no Prefix entries for skills/plugins/extensions dirs.
//   - collectFiles skipped Prefix entries entirely (no subtree walk).
//
// This test is the guard the spec meta-rule mandates: it uses real file I/O
// (a temp HOME with real files), the real allowlist, and the real collectFiles
// subtree walker — so it cannot be fooled by synthetic model.Signals injection.

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/aiagent"
	"github.com/jakelamon/keelix/internal/model"
)

// overrideHomeDir replaces os.UserHomeDir via the package-level hook in allowlist.go.
// Since we can't monkey-patch os.UserHomeDir, we rebuild the allowlist by
// temporarily replacing the homeRelativeEntries and re-running the init logic.
// This test uses the internal rebuildAllowlistForHome helper added for testing.
func TestRFX5_AGT005_CollectEmitsBackupFileFact(t *testing.T) {
	home := t.TempDir()

	// Create a backup file: ~/.claude.json.bak
	bakPath := filepath.Join(home, ".claude.json.bak")
	if err := os.WriteFile(bakPath, []byte(`{"saved":"backup"}`), 0o600); err != nil {
		t.Fatalf("write bak: %v", err)
	}

	// Also create the canonical file so the parent dir exists
	claudeJSON := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(claudeJSON, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write claude.json: %v", err)
	}

	// Rebuild the allowlist with our temp home so the Prefix entries resolve.
	rebuildAllowlistForHome(home)
	t.Cleanup(func() { rebuildAllowlistForDefaultHome() })

	sigs, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Verify that bakPath appears as an existing FileFact.
	var found bool
	for _, ff := range sigs.Files {
		if ff.Path == bakPath && ff.Exists {
			found = true
			break
		}
	}
	if !found {
		paths := make([]string, 0, len(sigs.Files))
		for _, ff := range sigs.Files {
			paths = append(paths, ff.Path)
		}
		t.Fatalf("RFX-5: FileFact for %q not found in collected files.\nAll paths: %v", bakPath, paths)
	}
}

func TestRFX5_AGT005_CheckFiresViaCollect(t *testing.T) {
	home := t.TempDir()

	// Create a backup file: ~/.claude.json.bak
	bakPath := filepath.Join(home, ".claude.json.bak")
	if err := os.WriteFile(bakPath, []byte(`{"saved":"backup"}`), 0o600); err != nil {
		t.Fatalf("write bak: %v", err)
	}

	rebuildAllowlistForHome(home)
	t.Cleanup(func() { rebuildAllowlistForDefaultHome() })

	sigs, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	c := findRegisteredCheck(t, "AGT005")
	ctx := &model.ScanContext{Collector: sigs}
	findings := c.Run(ctx)

	for _, f := range findings {
		if f.CheckID == "AGT005" && f.IsFail() {
			return // expected
		}
	}
	t.Fatalf("RFX-5: AGT005 did not fire for backup file %q.\nFindings: %+v\nFiles: %v",
		bakPath, findings, sigs.Files)
}

func TestRFX5_AGT010_CollectEmitsGitConfigFileFact(t *testing.T) {
	home := t.TempDir()

	// Create ~/.claude/skills/myplugin/.git/config
	gitConfigPath := filepath.Join(home, ".claude", "skills", "myplugin", ".git", "config")
	if err := os.MkdirAll(filepath.Dir(gitConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(gitConfigPath, []byte("[core]\nrepositoryformatversion = 0\n"), 0o644); err != nil {
		t.Fatalf("write git config: %v", err)
	}

	rebuildAllowlistForHome(home)
	t.Cleanup(func() { rebuildAllowlistForDefaultHome() })

	sigs, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var found bool
	for _, ff := range sigs.Files {
		if ff.Path == gitConfigPath && ff.Exists {
			found = true
			break
		}
	}
	if !found {
		paths := make([]string, 0, len(sigs.Files))
		for _, ff := range sigs.Files {
			paths = append(paths, ff.Path)
		}
		t.Fatalf("RFX-5: FileFact for %q not found in collected files.\nAll paths: %v", gitConfigPath, paths)
	}
}

func TestRFX5_AGT010_CheckFiresViaCollect(t *testing.T) {
	home := t.TempDir()

	// Create ~/.claude/skills/myplugin/.git/config
	gitConfigPath := filepath.Join(home, ".claude", "skills", "myplugin", ".git", "config")
	if err := os.MkdirAll(filepath.Dir(gitConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(gitConfigPath, []byte("[core]\nrepositoryformatversion = 0\n"), 0o644); err != nil {
		t.Fatalf("write git config: %v", err)
	}

	rebuildAllowlistForHome(home)
	t.Cleanup(func() { rebuildAllowlistForDefaultHome() })

	sigs, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	c := findRegisteredCheck(t, "AGT010")
	ctx := &model.ScanContext{Collector: sigs}
	findings := c.Run(ctx)

	for _, f := range findings {
		if f.CheckID == "AGT010" && f.IsFail() {
			return // expected
		}
	}
	t.Fatalf("RFX-5: AGT010 did not fire for git-backed skill at %q.\nFindings: %+v\nFiles: %v",
		gitConfigPath, findings, sigs.Files)
}

// TestRFX5_FileFact_NoDuplicates verifies that collectFiles deduplicates paths
// so that a file reachable via both an exact allowlist entry and an overlapping
// prefix walk appears only once in Signals.Files.
//
// The canonical example is ~/.claude/settings.json: it is listed as an exact
// entry AND is reachable by the ~/.claude MaxDepth=1 prefix walk. Before the
// dedup fix, checks like AGT004 and AGT005 would emit duplicate findings for
// the same resource.
func TestRFX5_FileFact_NoDuplicates(t *testing.T) {
	home := t.TempDir()

	// Create ~/.claude/settings.json — present as an exact entry AND inside the
	// ~/.claude Prefix walk. With the old code this yields two FileFacts.
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"defaultMode":"default"}`), 0o600); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	rebuildAllowlistForHome(home)
	t.Cleanup(func() { rebuildAllowlistForDefaultHome() })

	sigs, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	count := 0
	for _, ff := range sigs.Files {
		if ff.Path == settingsPath {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("RFX-5: expected exactly 1 FileFact for %q, got %d (deduplication broken)", settingsPath, count)
	}
}

// TestRFX5_AGT010_OpenclaWExtensions_CheckFiresViaCollect is the PARSER-FED
// regression test for the .openclaw/extensions gap in AGT010. It verifies that
// a git-backed extension at ~/.openclaw/extensions/<name>/.git/config is both
// collected and causes AGT010 to fire. Before the fix, extensionDirs did not
// include ".openclaw/extensions/" so AGT010 would silently pass.
func TestRFX5_AGT010_OpenclaWExtensions_CheckFiresViaCollect(t *testing.T) {
	home := t.TempDir()

	// Create ~/.openclaw/extensions/myext/.git/config
	gitConfigPath := filepath.Join(home, ".openclaw", "extensions", "myext", ".git", "config")
	if err := os.MkdirAll(filepath.Dir(gitConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(gitConfigPath, []byte("[core]\nrepositoryformatversion = 0\n"), 0o644); err != nil {
		t.Fatalf("write git config: %v", err)
	}

	rebuildAllowlistForHome(home)
	t.Cleanup(func() { rebuildAllowlistForDefaultHome() })

	sigs, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// First verify collectFiles actually emitted a FileFact for the git config.
	var collected bool
	for _, ff := range sigs.Files {
		if ff.Path == gitConfigPath && ff.Exists {
			collected = true
			break
		}
	}
	if !collected {
		paths := make([]string, 0, len(sigs.Files))
		for _, ff := range sigs.Files {
			paths = append(paths, ff.Path)
		}
		t.Fatalf("RFX-5: FileFact for %q not found in collected files.\nAll paths: %v", gitConfigPath, paths)
	}

	// Now verify AGT010 fires on the collected signals.
	c := findRegisteredCheck(t, "AGT010")
	ctx := &model.ScanContext{Collector: sigs}
	findings := c.Run(ctx)

	for _, f := range findings {
		if f.CheckID == "AGT010" && f.IsFail() {
			return // expected
		}
	}
	t.Fatalf("RFX-5: AGT010 did not fire for git-backed openclaw extension at %q.\nFindings: %+v\nFiles: %v",
		gitConfigPath, findings, sigs.Files)
}
