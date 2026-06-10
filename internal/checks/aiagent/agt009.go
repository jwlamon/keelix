package aiagent

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&agt009{}) }

type agt009 struct{}

func (c *agt009) ID() string              { return catalog.Get("AGT009").ID }
func (c *agt009) Title() string           { return catalog.Get("AGT009").Title }
func (c *agt009) Group() model.CheckGroup { return catalog.Get("AGT009").Group }

func (c *agt009) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT009")}
	}

	var reasons []string

	if oc, ok := ConfigBySchema(ctx.Collector, "openclaw-config"); ok {
		if oc.Values["channels.discord.groupPolicy"] == "open" {
			reasons = append(reasons, "channels.discord.groupPolicy=open")
		}
		if oc.Values["channels.telegram.dmPolicy"] == "open" {
			reasons = append(reasons, "channels.telegram.dmPolicy=open")
		}
	}

	if len(reasons) == 0 {
		return []model.Finding{catalog.Get("AGT009").Pass("No untrusted inbound channels configured as open.")}
	}

	f := catalog.Get("AGT009").Finding()
	f.ExposureClass = model.ExposureLocalhost
	f.Confidence = model.ConfidenceHigh
	f.Resource = "agent inbound channel policy"
	f.Evidence = joinReasons(reasons)
	f.Fix = model.Fix{
		Summary: "Set Discord groupPolicy and Telegram dmPolicy to 'allowlist' or 'deny'; never 'open'.",
	}
	return []model.Finding{f}
}
