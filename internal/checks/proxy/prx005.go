package proxy

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&prx005{}) }

type prx005 struct{}

func (c *prx005) ID() string              { return catalog.Get("PRX005").ID }
func (c *prx005) Title() string           { return catalog.Get("PRX005").Title }
func (c *prx005) Group() model.CheckGroup { return catalog.Get("PRX005").Group }

func (c *prx005) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Proxy == nil {
		return nil
	}

	var findings []model.Finding
	for _, route := range ctx.Stack.Proxy.Routes {
		if route.Wildcard {
			f := catalog.Get("PRX005").Finding()
			f.Service = route.Service
			f.Resource = route.Host
			f.Fix = model.Fix{
				Summary: "Replace the wildcard route with explicit host rules for each intended service.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("PRX005").Pass("No overly broad wildcard proxy routes found.")}
	}
	return findings
}
