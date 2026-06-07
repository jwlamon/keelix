package aiagent

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt001{}) }

type agt001 struct{}

func (c *agt001) ID() string              { return catalog.Get("AGT001").ID }
func (c *agt001) Title() string           { return catalog.Get("AGT001").Title }
func (c *agt001) Group() model.CheckGroup { return catalog.Get("AGT001").Group }

func (c *agt001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT001")}
	}

	var reasons []string

	// OpenClaw: tools.exec.ask == "off" means all exec approved without prompt.
	// "on-miss" is NOT auto-approval — only the literal "off" value fires.
	if oc, ok := ConfigBySchema(ctx.Collector, "openclaw-config"); ok {
		if oc.Values["tools.exec.ask"] == "off" {
			reasons = append(reasons, "openclaw tools.exec.ask=off")
		}
	}

	// Claude Code: defaultMode bypassPermissions or skipDangerousModePermissionPrompt true.
	if cs, ok := ConfigBySchema(ctx.Collector, "claude-code-settings"); ok {
		if cs.Values["defaultMode"] == "bypassPermissions" {
			reasons = append(reasons, "claude-code defaultMode=bypassPermissions")
		}
		if cs.Values["skipDangerousModePermissionPrompt"] == "true" {
			reasons = append(reasons, "claude-code skipDangerousModePermissionPrompt=true")
		}
	}

	// Codex: approval_policy == "auto" means all commands run without approval.
	if cc, ok := ConfigBySchema(ctx.Collector, "codex-config"); ok {
		if cc.Values["approval_policy"] == "auto" {
			reasons = append(reasons, "codex approval_policy=auto")
		}
	}

	if len(reasons) == 0 {
		return []model.Finding{catalog.Get("AGT001").Pass("No agent auto-approval configuration detected.")}
	}

	f := catalog.Get("AGT001").Finding()
	f.ExposureClass = model.ExposureLocalhost
	f.Confidence = model.ConfidenceMedium
	f.Resource = "agent configuration"
	f.Evidence = joinReasons(reasons)
	f.Fix = model.Fix{
		Summary: "Set OpenClaw tools.exec.ask to 'on-miss', set Claude defaultMode to 'default', set Codex approval_policy to 'suggest'.",
	}
	return []model.Finding{f}
}

// joinReasons concatenates a slice of strings with "; " separator.
func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}
