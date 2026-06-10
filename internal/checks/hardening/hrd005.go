package hardening

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd005{}) }

type hrd005 struct{}

func (c *hrd005) ID() string              { return catalog.Get("HRD005").ID }
func (c *hrd005) Title() string           { return catalog.Get("HRD005").Title }
func (c *hrd005) Group() model.CheckGroup { return catalog.Get("HRD005").Group }

func (c *hrd005) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD005")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if svc.ReadOnly {
			continue
		}
		f := catalog.Get("HRD005").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("container %s", svc.Name)
		f.Evidence = fmt.Sprintf("service %q does not set read_only: true", svc.Name)
		f.Fix = model.Fix{
			Summary: "Add `read_only: true` plus tmpfs or named volumes for any writable paths the service needs.",
			Diff:    "+    read_only: true",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD005").Pass("All containers have a read-only root filesystem.")}
	}
	return findings
}
