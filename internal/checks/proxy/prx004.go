package proxy

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&prx004{}) }

type prx004 struct{}

func (c *prx004) ID() string              { return catalog.Get("PRX004").ID }
func (c *prx004) Title() string           { return catalog.Get("PRX004").Title }
func (c *prx004) Group() model.CheckGroup { return catalog.Get("PRX004").Group }

func (c *prx004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Proxy == nil {
		return nil
	}

	var findings []model.Finding
	for _, route := range ctx.Stack.Proxy.Routes {
		if !route.SecurityHeaders {
			f := catalog.Get("PRX004").Finding()
			f.Service = route.Service
			f.Resource = route.Host
			f.Fix = model.Fix{
				Summary: "Add a headers middleware to set HSTS, X-Content-Type-Options, and X-Frame-Options on this route.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("PRX004").Pass("All public routes have security headers configured.")}
	}
	return findings
}
