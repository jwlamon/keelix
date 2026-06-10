package proxy

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&prx006{}) }

type prx006 struct{}

func (c *prx006) ID() string              { return catalog.Get("PRX006").ID }
func (c *prx006) Title() string           { return catalog.Get("PRX006").Title }
func (c *prx006) Group() model.CheckGroup { return catalog.Get("PRX006").Group }

func (c *prx006) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Proxy == nil {
		return nil
	}

	if ctx.Stack.Proxy.Kind != model.ProxyNPM {
		return []model.Finding{catalog.Get("PRX006").Pass("Proxy kind does not use known default credentials.")}
	}

	f := catalog.Get("PRX006").Finding()
	f.Evidence = "Nginx Proxy Manager ships with default credentials: admin@example.com / changeme."
	f.Fix = model.Fix{
		Summary: "Verify that the default Nginx Proxy Manager admin login (admin@example.com / changeme) has been changed to a strong, unique password.",
	}
	return []model.Finding{f}
}
