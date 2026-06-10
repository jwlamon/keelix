package aiagent_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/collect"
	"github.com/jakelamon/keelix/internal/model"
)

func TestAGT010_UnpinnedGitExtension(t *testing.T) {
	c := findCheck(t, "AGT010")
	// A skill path that is a git URL without a pinned ref.
	sigs := &model.Signals{
		Files: []model.FileFact{
			// An extension directory that contains a .git subdirectory (heuristic: non-official).
			{Path: "/home/user/.openclaw/skills/myplugin/.git/config", Exists: true, Mode: "0644"},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT010" && f.IsFail() {
			found = true
			if f.Confidence != model.ConfidenceMedium {
				t.Errorf("AGT010: want ConfidenceMedium, got %v", f.Confidence)
			}
		}
	}
	if !found {
		t.Fatal("AGT010: want failing finding for git-backed unpinned skill")
	}
}

func TestAGT010_OfficialSkill_Pass(t *testing.T) {
	c := findCheck(t, "AGT010")
	// A skill that does NOT have a .git directory — treated as official/pinned.
	sigs := &model.Signals{
		Files: []model.FileFact{
			{Path: "/home/user/.openclaw/skills/official-tool/skill.yaml", Exists: true, Mode: "0644"},
		},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT010" && f.IsFail() {
			t.Errorf("AGT010: official skill without .git should pass, got %+v", f)
		}
	}
}

func TestAGT010_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT010")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT010: want NotAssessed, got %+v", findings)
	}
}

// TestAGT010_CollectorFed_UnpinnedGitExtension is the PARSER-FED regression
// case for RFX-5. It exercises the full collect.Collect pipeline against a
// temp HOME containing ~/.claude/skills/myplugin/.git/config, then feeds the
// resulting *model.Signals directly to AGT010. This guards against regressions
// where collectFiles skipped Prefix entries entirely (no subtree walker).
func TestAGT010_CollectorFed_UnpinnedGitExtension(t *testing.T) {
	home := t.TempDir()

	// Create ~/.claude/skills/myplugin/.git/config — a git-backed extension.
	gitConfigPath := filepath.Join(home, ".claude", "skills", "myplugin", ".git", "config")
	if err := os.MkdirAll(filepath.Dir(gitConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(gitConfigPath, []byte("[core]\nrepositoryformatversion = 0\n"), 0o644); err != nil {
		t.Fatalf("write git config: %v", err)
	}

	collect.RebuildAllowlistForHome(home)
	t.Cleanup(collect.RebuildAllowlistForDefaultHome)

	sigs, err := collect.Collect(collect.Options{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	c := findCheck(t, "AGT010")
	ctx := &model.ScanContext{Collector: sigs}
	findings := c.Run(ctx)

	for _, f := range findings {
		if f.CheckID == "AGT010" && f.IsFail() {
			return // expected: unpinned git extension detected
		}
	}
	t.Fatalf("RFX-5: AGT010 did not fire for git-backed skill at %q.\nFindings: %+v\nFiles: %v",
		gitConfigPath, findings, sigs.Files)
}
