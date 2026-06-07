package hardening

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hrd007{}) }

type hrd007 struct{}

func (c *hrd007) ID() string              { return catalog.Get("HRD007").ID }
func (c *hrd007) Title() string           { return catalog.Get("HRD007").Title }
func (c *hrd007) Group() model.CheckGroup { return catalog.Get("HRD007").Group }

func (c *hrd007) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD007")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if svc.Deploy != nil && svc.Deploy.HasLimits {
			continue
		}
		f := catalog.Get("HRD007").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("container %s", svc.Name)
		f.Evidence = fmt.Sprintf("service %q has no deploy.resources.limits configured", svc.Name)
		f.Fix = model.Fix{
			Summary: "Set deploy.resources.limits.memory and cpus to prevent a single container exhausting host resources.",
			Diff: `+    deploy:
+      resources:
+        limits:
+          memory: 512m
+          cpus: "0.5"`,
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD007").Pass("All containers have resource limits configured.")}
	}
	return findings
}
