// Package hardening implements container-hardening checks (HRD*).
package hardening

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd001{}) }

type hrd001 struct{}

func (c *hrd001) ID() string              { return catalog.Get("HRD001").ID }
func (c *hrd001) Title() string           { return catalog.Get("HRD001").Title }
func (c *hrd001) Group() model.CheckGroup { return catalog.Get("HRD001").Group }

func (c *hrd001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD001")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if !svc.Privileged {
			continue
		}
		f := catalog.Get("HRD001").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("container %s", svc.Name)
		f.Evidence = fmt.Sprintf("service %q has privileged: true", svc.Name)
		f.Fix = model.Fix{
			Summary: "Remove `privileged: true`; grant only specific capabilities if needed.",
			Diff:    "- privileged: true",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD001").Pass("No containers run in privileged mode.")}
	}
	return findings
}
