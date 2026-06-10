package hardening

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd003{}) }

type hrd003 struct{}

func (c *hrd003) ID() string              { return catalog.Get("HRD003").ID }
func (c *hrd003) Title() string           { return catalog.Get("HRD003").Title }
func (c *hrd003) Group() model.CheckGroup { return catalog.Get("HRD003").Group }

func (c *hrd003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD003")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if !svc.MountsDockerSocket() {
			continue
		}
		f := catalog.Get("HRD003").Finding()
		f.Service = svc.Name
		f.Resource = "/var/run/docker.sock"
		f.Evidence = fmt.Sprintf("service %q mounts /var/run/docker.sock", svc.Name)
		f.Fix = model.Fix{
			Summary: "Remove the /var/run/docker.sock mount; use a socket proxy with least privilege if API access is required.",
			Diff:    "- - /var/run/docker.sock:/var/run/docker.sock",
			DocURL:  "https://github.com/Tecnativa/docker-socket-proxy",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD003").Pass("No containers mount the Docker socket.")}
	}
	return findings
}
