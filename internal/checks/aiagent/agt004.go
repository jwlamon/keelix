package aiagent

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt004{}) }

type agt004 struct{}

func (c *agt004) ID() string              { return catalog.Get("AGT004").ID }
func (c *agt004) Title() string           { return catalog.Get("AGT004").Title }
func (c *agt004) Group() model.CheckGroup { return catalog.Get("AGT004").Group }

// agentTokenPaths are path substrings that identify agent credential/token files.
var agentTokenPaths = []string{
	".openclaw/openclaw.json",
	".openclaw/exec-approvals.json",
	".openclaw/cron/jobs.json",
	".claude/settings.json",
	".claude/settings.local.json",
	".claude.json",
	".codex/config.toml",
	".codex/config.json",
	".codex/auth.json",
}

// isAgentTokenFile reports whether path matches a known agent credential file.
func isAgentTokenFile(path string) bool {
	for _, suffix := range agentTokenPaths {
		if strings.Contains(path, suffix) {
			return true
		}
	}
	return false
}

// modeExceedsLimit returns true if octalStr has any group or other permission bits set.
// Owner-only modes (0600, 0700) are fine; only flag when group/other bits are present.
func modeExceedsLimit(octalStr string) bool {
	if octalStr == "" {
		return false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(octalStr, "0"), 8, 32)
	if err != nil {
		return false
	}
	// 0077 masks all group and other bits. Non-zero means group or world access is granted.
	return n&0077 != 0
}

func (c *agt004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT004")}
	}

	var findings []model.Finding
	for _, ff := range ctx.Collector.Files {
		if !ff.Exists || !isAgentTokenFile(ff.Path) {
			continue
		}
		if !modeExceedsLimit(ff.Mode) {
			continue
		}
		f := catalog.Get("AGT004").Finding()
		f.ExposureClass = model.ExposureLocalhost
		f.Confidence = model.ConfidenceHigh
		f.Resource = ff.Path
		f.Evidence = fmt.Sprintf("file %s has mode %s (want <= 0600)", ff.Path, ff.Mode)
		f.Fix = model.Fix{
			Summary:  fmt.Sprintf("Restrict permissions: chmod 0600 %s", ff.Path),
			Commands: []string{fmt.Sprintf("chmod 0600 %s", ff.Path)},
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("AGT004").Pass("Agent credential files have safe permissions.")}
	}
	return findings
}
