package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc041{}) }

type svc041 struct{}

func (c *svc041) ID() string              { return catalog.Get("SVC041").ID }
func (c *svc041) Title() string           { return catalog.Get("SVC041").Title }
func (c *svc041) Group() model.CheckGroup { return catalog.Get("SVC041").Group }

func (c *svc041) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC041")}
	}
	cf, ok := configBySchema(ctx.Collector, "nfs-exports")
	if !ok {
		return []model.Finding{notAssessed("SVC041")}
	}
	noRootSquash := cf.Values["no_root_squash"] == "true"
	worldExport := cf.Values["world-export"] == "true"
	if !noRootSquash && !worldExport {
		return []model.Finding{catalog.Get("SVC041").Pass("NFS exports do not use no_root_squash and are not world-exported.")}
	}
	f := catalog.Get("SVC041").Finding()
	f.Resource = "/etc/exports"
	f.Metadata = map[string]string{"port": "2049"}
	switch {
	case noRootSquash && worldExport:
		f.Evidence = "no_root_squash=true; world-export=true"
	case noRootSquash:
		f.Evidence = "no_root_squash=true (remote root maps to local root)"
	default:
		f.Evidence = "world-export=true (export accessible from 0.0.0.0/0 or *)"
	}
	f.Fix = model.Fix{
		Summary:  "Replace no_root_squash with root_squash in /etc/exports and restrict exports to specific host/subnet instead of * or 0.0.0.0/0. Run `exportfs -ra` after changes.",
		Commands: []string{"exportfs -ra"},
	}
	return []model.Finding{f}
}
