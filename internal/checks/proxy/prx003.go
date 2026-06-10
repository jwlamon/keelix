package proxy

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&prx003{}) }

type prx003 struct{}

func (c *prx003) ID() string              { return catalog.Get("PRX003").ID }
func (c *prx003) Title() string           { return catalog.Get("PRX003").Title }
func (c *prx003) Group() model.CheckGroup { return catalog.Get("PRX003").Group }

func (c *prx003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Proxy == nil {
		return nil
	}

	if !ctx.Stack.Proxy.DashboardExposed {
		return []model.Finding{catalog.Get("PRX003").Pass("Reverse-proxy admin dashboard is not exposed insecurely.")}
	}

	f := catalog.Get("PRX003").Finding()
	if ctx.Stack.Proxy.Kind == model.ProxyTraefik {
		f.Evidence = "Traefik api.insecure=true exposes the dashboard and API without authentication."
		f.Fix = model.Fix{
			Summary: "Remove api.insecure=true from the Traefik configuration and protect the dashboard with an auth middleware.",
		}
	} else {
		f.Fix = model.Fix{
			Summary: "Restrict access to the reverse-proxy admin dashboard; require authentication and avoid exposing it publicly.",
		}
	}
	return []model.Finding{f}
}
