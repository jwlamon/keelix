package hardening

import (
	"fmt"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd010{}) }

type hrd010 struct{}

func (c *hrd010) ID() string              { return catalog.Get("HRD010").ID }
func (c *hrd010) Title() string           { return catalog.Get("HRD010").Title }
func (c *hrd010) Group() model.CheckGroup { return catalog.Get("HRD010").Group }

// agentComms mirrors internal/checks/aiagent.agentComms to avoid double-firing
// with AGT003 which already covers the agent process's docker-group membership.
var agentComms = []string{"openclaw", "claude", "claude-code", "codex", "cursor", "windsurf"}

func isAgentComm(comm string) bool {
	lower := strings.ToLower(comm)
	for _, a := range agentComms {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
}

func (c *hrd010) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HRD010")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("HRD010")}
	}

	// Deduplicate findings by UID — one finding per affected non-root user.
	seen := make(map[int]bool)
	var findings []model.Finding

	for _, proc := range ctx.Collector.Processes {
		// Skip root processes.
		if proc.UID == 0 {
			continue
		}
		// Skip agent processes — already covered by AGT003.
		if isAgentComm(proc.Comm) {
			continue
		}
		// Skip UIDs already reported.
		if seen[proc.UID] {
			continue
		}
		// Check for docker group membership.
		for _, grp := range proc.Groups {
			if strings.ToLower(grp) == "docker" {
				seen[proc.UID] = true
				f := catalog.Get("HRD010").Finding()
				f.Resource = fmt.Sprintf("uid %d (%s)", proc.UID, proc.Comm)
				f.Evidence = fmt.Sprintf(
					"non-root user (uid %d, process %q) is a member of the docker group — equivalent to passwordless root on the host",
					proc.UID, proc.Comm,
				)
				f.Fix = model.Fix{
					Summary: "Remove the user from the docker group; prefer rootless Docker or a dedicated non-interactive service account for Docker API access.",
					Commands: []string{
						fmt.Sprintf("# Identify the user: getent passwd %d", proc.UID),
						"# Then: gpasswd -d <username> docker",
						"# Or switch to rootless Docker: dockerd-rootless-setuptool.sh install",
					},
				}
				findings = append(findings, f)
				break
			}
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD010").Pass("No non-root interactive user found in the docker group (outside of agent processes).")}
	}
	return findings
}
