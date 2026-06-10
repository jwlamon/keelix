package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc020{}) }

type svc020 struct{}

func (c *svc020) ID() string              { return catalog.Get("SVC020").ID }
func (c *svc020) Title() string           { return catalog.Get("SVC020").Title }
func (c *svc020) Group() model.CheckGroup { return catalog.Get("SVC020").Group }

func (c *svc020) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC020")}
	}
	cf, ok := configBySchema(ctx.Collector, "grafana-ini")
	if !ok {
		return []model.Finding{notAssessed("SVC020")}
	}
	anonEnabled := cf.Values["auth.anonymous.enabled"] == "true"
	defaultAdmin := cf.Values["admin.default"] == "true"
	if !anonEnabled && !defaultAdmin {
		return []model.Finding{catalog.Get("SVC020").Pass("Grafana anonymous access is disabled and default admin credentials are changed.")}
	}
	f := catalog.Get("SVC020").Finding()
	f.Resource = "grafana"
	f.Metadata = map[string]string{"port": "3000"}
	switch {
	case anonEnabled && defaultAdmin:
		f.Evidence = "auth.anonymous.enabled=true; admin.default=true"
	case anonEnabled:
		f.Evidence = "auth.anonymous.enabled=true"
	default:
		f.Evidence = "admin.default=true (default admin/admin credentials unchanged)"
	}
	f.Fix = model.Fix{
		Summary: "Disable [auth.anonymous] enabled in grafana.ini and change the default admin password via the Grafana UI or GF_SECURITY_ADMIN_PASSWORD env var.",
		Diff:    "[auth.anonymous]\nenabled = false",
	}
	return []model.Finding{f}
}
