package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc021{}) }

type svc021 struct{}

func (c *svc021) ID() string              { return catalog.Get("SVC021").ID }
func (c *svc021) Title() string           { return catalog.Get("SVC021").Title }
func (c *svc021) Group() model.CheckGroup { return catalog.Get("SVC021").Group }

func (c *svc021) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC021")}
	}
	cf, ok := configBySchema(ctx.Collector, "prometheus-yml")
	if !ok {
		return []model.Finding{notAssessed("SVC021")}
	}
	// prometheus.yml only holds outbound scrape-side auth; inbound API
	// authentication is configured in a separate web.yml passed via
	// --web.config.file. We cannot determine API auth from prometheus.yml
	// alone. Return NotAssessed rather than a false FAIL.
	if cf.Values["auth.determinable"] == "false" {
		f := notAssessed("SVC021")
		f.Detail = "API auth is configured in web.yml which is not bind-mounted; cannot determine whether Prometheus API authentication is enabled. Bind-mount web.yml and re-run with --collect."
		return []model.Finding{f}
	}
	// Fallthrough: if a future parser variant can determine auth (e.g. web.yml
	// support is added), handle it here. Until then the above branch is always
	// taken for a prometheus-yml fact.
	return []model.Finding{notAssessed("SVC021")}
}
