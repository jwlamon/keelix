// Package proxy implements reverse-proxy checks (PRX*).
package proxy

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&prx001{}) }

type prx001 struct{}

func (c *prx001) ID() string              { return catalog.Get("PRX001").ID }
func (c *prx001) Title() string           { return catalog.Get("PRX001").Title }
func (c *prx001) Group() model.CheckGroup { return catalog.Get("PRX001").Group }

func (c *prx001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Proxy == nil {
		return nil
	}

	var findings []model.Finding
	for _, route := range ctx.Stack.Proxy.Routes {
		if !route.HasAuth {
			f := catalog.Get("PRX001").Finding()
			f.Service = route.Service
			f.Resource = route.Host
			f.Fix = model.Fix{
				Summary: "Add an auth middleware / forward-auth (Authelia/Authentik) or basic auth in front of this route.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("PRX001").Pass("All public routes have authentication configured.")}
	}
	return findings
}
