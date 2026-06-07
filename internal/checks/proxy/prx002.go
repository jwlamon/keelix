package proxy

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&prx002{}) }

type prx002 struct{}

func (c *prx002) ID() string              { return catalog.Get("PRX002").ID }
func (c *prx002) Title() string           { return catalog.Get("PRX002").Title }
func (c *prx002) Group() model.CheckGroup { return catalog.Get("PRX002").Group }

func (c *prx002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Proxy == nil {
		return nil
	}

	var findings []model.Finding
	for _, route := range ctx.Stack.Proxy.Routes {
		if !route.TLS {
			f := catalog.Get("PRX002").Finding()
			f.Service = route.Service
			f.Resource = route.Host
			f.Fix = model.Fix{
				Summary: "Enable TLS (e.g. Let's Encrypt) on this route and redirect HTTP to HTTPS.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("PRX002").Pass("All public routes are served over TLS.")}
	}
	return findings
}
