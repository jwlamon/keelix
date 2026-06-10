package aiagent

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&agt007{}) }

type agt007 struct{}

func (c *agt007) ID() string              { return catalog.Get("AGT007").ID }
func (c *agt007) Title() string           { return catalog.Get("AGT007").Title }
func (c *agt007) Group() model.CheckGroup { return catalog.Get("AGT007").Group }

// isAutoApproval returns true if the AGT001 auto-approval condition is met for the given signals.
// This mirrors the AGT001 logic without creating a dependency on the struct.
func isAutoApproval(sigs *model.Signals) bool {
	if oc, ok := ConfigBySchema(sigs, "openclaw-config"); ok {
		if oc.Values["tools.exec.ask"] == "off" {
			return true
		}
	}
	if cs, ok := ConfigBySchema(sigs, "claude-code-settings"); ok {
		if cs.Values["defaultMode"] == "bypassPermissions" {
			return true
		}
		if cs.Values["skipDangerousModePermissionPrompt"] == "true" {
			return true
		}
	}
	if cc, ok := ConfigBySchema(sigs, "codex-config"); ok {
		if cc.Values["approval_policy"] == "auto" {
			return true
		}
	}
	return false
}

func (c *agt007) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT007")}
	}

	cronEnabled := false
	if cron, ok := ConfigBySchema(ctx.Collector, "openclaw-cron"); ok {
		cronEnabled = cron.Values["anyEnabled"] == "true"
	}

	if !cronEnabled {
		return []model.Finding{catalog.Get("AGT007").Pass("No unattended cron/loop job with auto-approval detected.")}
	}

	if !isAutoApproval(ctx.Collector) {
		return []model.Finding{catalog.Get("AGT007").Pass("Scheduled jobs present but auto-approval is not enabled.")}
	}

	f := catalog.Get("AGT007").Finding()
	f.ExposureClass = model.ExposureLocalhost
	f.Confidence = model.ConfidenceMedium
	f.Resource = "openclaw cron + agent auto-approval"
	f.Evidence = "openclaw-cron anyEnabled=true AND at least one agent auto-approval condition is set"
	f.Fix = model.Fix{
		Summary: "Disable scheduled agent jobs or enable approval prompts (set tools.exec.ask to 'on-miss' or 'always').",
	}
	return []model.Finding{f}
}
