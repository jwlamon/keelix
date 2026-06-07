package firewall

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&fw003{}) }

type fw003 struct{}

func (c *fw003) ID() string              { return catalog.Get("FW003").ID }
func (c *fw003) Title() string           { return catalog.Get("FW003").Title }
func (c *fw003) Group() model.CheckGroup { return catalog.Get("FW003").Group }

func (c *fw003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("FW003")}
	}

	var findings []model.Finding

	for _, svc := range ctx.Stack.Services {
		if svc.NetworkMode != "host" {
			continue
		}
		f := catalog.Get("FW003").Finding()
		f.Service = svc.Name
		f.Resource = "network_mode: host"
		f.Evidence = "service \"" + svc.Name + "\" uses network_mode: host, removing Docker network isolation"
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("FW003").Pass("No services use host network mode.")}
	}
	return findings
}
