package service

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&svc060{}) }

type svc060 struct{}

func (c *svc060) ID() string              { return catalog.Get("SVC060").ID }
func (c *svc060) Title() string           { return catalog.Get("SVC060").Title }
func (c *svc060) Group() model.CheckGroup { return catalog.Get("SVC060").Group }

func (c *svc060) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC060")}
	}
	cf, ok := configBySchema(ctx.Collector, "traefik-yml")
	if !ok {
		return []model.Finding{notAssessed("SVC060")}
	}
	if cf.Values["api.insecure"] != "true" {
		return []model.Finding{catalog.Get("SVC060").Pass("Traefik API/dashboard is not exposed insecurely.")}
	}
	f := catalog.Get("SVC060").Finding()
	f.Resource = "traefik api"
	f.Evidence = "api.insecure=true"
	f.Metadata = map[string]string{"port": "8080"}
	f.Fix = model.Fix{
		Summary: "Remove api.insecure=true from traefik.yml. Expose the dashboard only via an authenticated router with middleware (e.g. BasicAuth or ForwardAuth).",
		Diff:    "api:\n  insecure: true  ->  (remove or set insecure: false)",
		DocURL:  "https://doc.traefik.io/traefik/operations/api/#insecure",
	}
	return []model.Finding{f}
}
