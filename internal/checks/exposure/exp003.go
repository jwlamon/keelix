package exposure

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&exp003{}) }

type exp003 struct{}

func (c *exp003) ID() string              { return catalog.Get("EXP003").ID }
func (c *exp003) Title() string           { return catalog.Get("EXP003").Title }
func (c *exp003) Group() model.CheckGroup { return catalog.Get("EXP003").Group }

func (c *exp003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}

	var findings []model.Finding

	for _, svc := range ctx.Stack.Services {
		for _, pm := range svc.Ports {
			if !pm.PublishedToAllInterfaces() || pm.HostPort == 0 {
				continue
			}
			if ctx.Probe.IsReachable(pm.HostPort) {
				continue
			}
			f := catalog.Get("EXP003").Finding()
			f.Service = svc.Name
			f.Resource = fmt.Sprintf("port %d", pm.HostPort)
			f.Evidence = fmt.Sprintf("port %d is declared in Compose but is not reachable from outside", pm.HostPort)
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("EXP003").Pass("All declared public ports are reachable.")}
	}
	return findings
}
