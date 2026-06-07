package hardening

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hrd004{}) }

type hrd004 struct{}

func (c *hrd004) ID() string              { return catalog.Get("HRD004").ID }
func (c *hrd004) Title() string           { return catalog.Get("HRD004").Title }
func (c *hrd004) Group() model.CheckGroup { return catalog.Get("HRD004").Group }

func (c *hrd004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD004")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if !svc.RunsAsRoot() {
			continue
		}
		f := catalog.Get("HRD004").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("container %s", svc.Name)
		f.Evidence = fmt.Sprintf(
			"service %q has no explicit non-root user configured (user: %q); some official images require root — verify before changing",
			svc.Name, svc.User,
		)
		f.Fix = model.Fix{
			Summary: `Add user: "1000:1000" (a non-root uid:gid). Note: some official images require root; verify the image supports non-root before applying.`,
			Diff:    `+    user: "1000:1000"`,
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD004").Pass("All containers run as a non-root user.")}
	}
	return findings
}
