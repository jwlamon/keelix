package aiagent

import (
	"fmt"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&agt003{}) }

type agt003 struct{}

func (c *agt003) ID() string              { return catalog.Get("AGT003").ID }
func (c *agt003) Title() string           { return catalog.Get("AGT003").Title }
func (c *agt003) Group() model.CheckGroup { return catalog.Get("AGT003").Group }

// agentComms are the process names that identify AI agent processes.
var agentComms = []string{"openclaw", "claude", "claude-code", "codex", "cursor", "windsurf"}

// criticalGroups drive Critical on Linux (no VM boundary).
var criticalGroups = []string{"sudo", "wheel", "docker"}

// warnGroups drive Warning regardless of OS.
var warnGroups = []string{"admin"}

func isAgentProcess(comm string) bool {
	lower := strings.ToLower(comm)
	for _, a := range agentComms {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
}

func (c *agt003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT003")}
	}

	linux := ctx.Collector.Platform.OS == "linux"
	var findings []model.Finding

	for _, proc := range ctx.Collector.Processes {
		if !isAgentProcess(proc.Comm) {
			continue
		}
		for _, grp := range proc.Groups {
			lower := strings.ToLower(grp)

			// docker group: Critical on Linux (no VM boundary), Warning on macOS.
			if lower == "docker" {
				f := catalog.Get("AGT003").Finding()
				if linux {
					f.Severity = model.SeverityCritical
					f.BaseImpact = 9.0
				}
				f.ExposureClass = model.ExposureLocalhost
				f.Confidence = model.ConfidenceHigh
				f.Resource = fmt.Sprintf("process %s (pid %d)", proc.Comm, proc.PID)
				f.Evidence = fmt.Sprintf("agent process %q is member of group %q", proc.Comm, grp)
				f.Fix = model.Fix{
					Summary: "Remove the agent process user from the docker group; use rootless Docker or a dedicated service account.",
				}
				findings = append(findings, f)
				continue
			}

			// sudo/wheel: Critical on Linux.
			isCriticalGroup := false
			for _, cg := range criticalGroups {
				if lower == cg {
					isCriticalGroup = true
					break
				}
			}
			isWarnGroup := false
			for _, wg := range warnGroups {
				if lower == wg {
					isWarnGroup = true
					break
				}
			}

			if isCriticalGroup || isWarnGroup {
				f := catalog.Get("AGT003").Finding()
				if isCriticalGroup && linux {
					f.Severity = model.SeverityCritical
					f.BaseImpact = 9.0
				}
				f.ExposureClass = model.ExposureLocalhost
				f.Confidence = model.ConfidenceHigh
				f.Resource = fmt.Sprintf("process %s (pid %d)", proc.Comm, proc.PID)
				f.Evidence = fmt.Sprintf("agent process %q is member of group %q", proc.Comm, grp)
				f.Fix = model.Fix{
					Summary: fmt.Sprintf("Remove the agent process user from the %s group; apply least-privilege.", grp),
				}
				findings = append(findings, f)
			}
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("AGT003").Pass("No agent process found in privileged groups.")}
	}
	return findings
}
