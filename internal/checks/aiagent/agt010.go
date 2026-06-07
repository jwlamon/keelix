package aiagent

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt010{}) }

type agt010 struct{}

func (c *agt010) ID() string              { return catalog.Get("AGT010").ID }
func (c *agt010) Title() string           { return catalog.Get("AGT010").Title }
func (c *agt010) Group() model.CheckGroup { return catalog.Get("AGT010").Group }

// extensionDirs are path substrings that identify agent extension/skill directories.
var extensionDirs = []string{
	".openclaw/extensions/",
	".openclaw/skills/",
	".openclaw/plugins/",
	".claude/skills/",
	".claude/plugins/",
}

// isExtensionPath returns true if the path is under a known extension directory.
func isExtensionPath(path string) bool {
	for _, dir := range extensionDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	return false
}

// isUnpinnedGitExtension returns true when a .git/config file is found under
// an extension directory — the heuristic for a git-backed (potentially unpinned) extension.
func isUnpinnedGitExtension(path string) bool {
	return isExtensionPath(path) && strings.HasSuffix(path, "/.git/config")
}

func (c *agt010) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT010")}
	}

	var findings []model.Finding
	seen := map[string]struct{}{}

	for _, ff := range ctx.Collector.Files {
		if !ff.Exists || !isUnpinnedGitExtension(ff.Path) {
			continue
		}
		// Extract the extension directory name from the path.
		// Path is like: .../.openclaw/skills/<name>/.git/config
		//            or .../.openclaw/extensions/<name>/.git/config
		parts := strings.Split(ff.Path, "/")
		extName := ""
		for i, p := range parts {
			if (p == "skills" || p == "plugins" || p == "extensions") && i+1 < len(parts) {
				extName = parts[i+1]
				break
			}
		}
		if extName == "" {
			extName = ff.Path
		}
		if _, dup := seen[extName]; dup {
			continue
		}
		seen[extName] = struct{}{}

		f := catalog.Get("AGT010").Finding()
		f.ExposureClass = model.ExposureLocalhost
		f.Confidence = model.ConfidenceMedium
		f.Resource = fmt.Sprintf("extension %s", extName)
		f.Evidence = fmt.Sprintf("agent extension %q is git-backed (non-official); no version pin detected", extName)
		f.Fix = model.Fix{
			Summary: fmt.Sprintf("Pin extension %q to a specific git tag or commit hash; prefer official marketplace sources.", extName),
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("AGT010").Pass("No unpinned non-official agent extensions detected.")}
	}
	return findings
}
