package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc003{}) }

type svc003 struct{}

func (c *svc003) ID() string              { return catalog.Get("SVC003").ID }
func (c *svc003) Title() string           { return catalog.Get("SVC003").Title }
func (c *svc003) Group() model.CheckGroup { return catalog.Get("SVC003").Group }

func (c *svc003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC003")}
	}
	cf, ok := configBySchema(ctx.Collector, "pg-hba")
	if !ok {
		return []model.Finding{notAssessed("SVC003")}
	}

	if cf.Values["trust.nonlocal"] == "true" {
		f := catalog.Get("SVC003").Finding()
		f.Resource = "postgresql"
		f.Evidence = "pg_hba.conf has trust auth method for a non-local host entry"
		f.Metadata = map[string]string{"port": "5432"}
		f.Fix = model.Fix{
			Summary: "Replace 'trust' with 'scram-sha-256' (or 'md5') for all non-local host entries in pg_hba.conf and reload PostgreSQL.",
			Diff:    "# host  all  all  0.0.0.0/0  trust  ->  scram-sha-256",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC003").Pass("PostgreSQL pg_hba.conf has no trust auth for non-local hosts.")}
}
