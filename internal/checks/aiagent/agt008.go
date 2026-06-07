package aiagent

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt008{}) }

type agt008 struct{}

func (c *agt008) ID() string              { return catalog.Get("AGT008").ID }
func (c *agt008) Title() string           { return catalog.Get("AGT008").Title }
func (c *agt008) Group() model.CheckGroup { return catalog.Get("AGT008").Group }

func (c *agt008) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT008")}
	}

	var reasons []string

	if oc, ok := ConfigBySchema(ctx.Collector, "openclaw-config"); ok {
		if oc.Values["tools.fs.workspaceOnly"] == "false" {
			reasons = append(reasons, "openclaw tools.fs.workspaceOnly=false (unrestricted filesystem access)")
		}
	}

	// Claude broad permissions.allow globs.
	for _, schema := range []string{"claude-code-settings", "claude-json", "claude-desktop-config"} {
		if cs, ok := ConfigBySchema(ctx.Collector, schema); ok {
			for k, v := range cs.Values {
				if strings.HasPrefix(k, "permissions.allow.") && (v == "**" || v == "~/**") {
					reasons = append(reasons, schema+": permissions.allow glob "+v)
				}
			}
		}
	}

	if len(reasons) == 0 {
		return []model.Finding{catalog.Get("AGT008").Pass("No whole-disk filesystem access configuration detected.")}
	}

	f := catalog.Get("AGT008").Finding()
	f.ExposureClass = model.ExposureLocalhost
	f.Confidence = model.ConfidenceHigh
	f.Resource = "agent filesystem permissions"
	f.Evidence = joinReasons(reasons)
	f.Fix = model.Fix{
		Summary: "Set openclaw fs.workspaceOnly=true; restrict Claude permissions.allow to specific paths instead of ** globs.",
	}
	return []model.Finding{f}
}
