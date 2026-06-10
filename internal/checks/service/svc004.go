package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc004{}) }

type svc004 struct{}

func (c *svc004) ID() string              { return catalog.Get("SVC004").ID }
func (c *svc004) Title() string           { return catalog.Get("SVC004").Title }
func (c *svc004) Group() model.CheckGroup { return catalog.Get("SVC004").Group }

func (c *svc004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC004")}
	}
	cf, ok := configBySchema(ctx.Collector, "elasticsearch-yml")
	if !ok {
		return []model.Finding{notAssessed("SVC004")}
	}

	if cf.Values["xpack.security.enabled"] != "true" {
		f := catalog.Get("SVC004").Finding()
		f.Resource = "elasticsearch"
		f.Evidence = "xpack.security.enabled = " + cf.Values["xpack.security.enabled"]
		f.Metadata = map[string]string{"port": "9200"}
		f.Fix = model.Fix{
			Summary: "Set xpack.security.enabled: true in elasticsearch.yml and restart Elasticsearch.",
			Diff:    "xpack.security.enabled: true",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC004").Pass("Elasticsearch X-Pack security is enabled.")}
}
