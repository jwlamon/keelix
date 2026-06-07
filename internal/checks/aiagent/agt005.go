package aiagent

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt005{}) }

type agt005 struct{}

func (c *agt005) ID() string              { return catalog.Get("AGT005").ID }
func (c *agt005) Title() string           { return catalog.Get("AGT005").Title }
func (c *agt005) Group() model.CheckGroup { return catalog.Get("AGT005").Group }

// backupSuffixes are file-extension patterns that indicate a backup copy of an agent config.
var backupSuffixes = []string{".bak", ".backup", ".old", ".orig", ".copy", "~"}

func isBackupFile(path string) bool {
	lower := strings.ToLower(path)
	for _, suffix := range backupSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func (c *agt005) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT005")}
	}

	var findings []model.Finding
	for _, ff := range ctx.Collector.Files {
		if !ff.Exists {
			continue
		}
		// A file that is both an agent token path base AND has a backup suffix.
		baseIsAgent := false
		for _, suffix := range backupSuffixes {
			candidate := strings.TrimSuffix(ff.Path, suffix)
			if isAgentTokenFile(candidate) {
				baseIsAgent = true
				break
			}
		}
		if !baseIsAgent && !isBackupFile(ff.Path) {
			continue
		}
		if !isBackupFile(ff.Path) {
			continue
		}
		f := catalog.Get("AGT005").Finding()
		f.ExposureClass = model.ExposureLocalhost
		f.Confidence = model.ConfidenceLow
		f.Resource = ff.Path
		f.Evidence = fmt.Sprintf("backup copy of agent credential file found: %s", ff.Path)
		f.Fix = model.Fix{
			Summary:  fmt.Sprintf("Remove backup file %s; it may contain plaintext secrets.", ff.Path),
			Commands: []string{fmt.Sprintf("rm -f %s", ff.Path)},
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("AGT005").Pass("No agent credential backup sprawl detected.")}
	}
	return findings
}
