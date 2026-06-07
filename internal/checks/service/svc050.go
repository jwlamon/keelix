package service

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&svc050{}) }

type svc050 struct{}

func (c *svc050) ID() string              { return catalog.Get("SVC050").ID }
func (c *svc050) Title() string           { return catalog.Get("SVC050").Title }
func (c *svc050) Group() model.CheckGroup { return catalog.Get("SVC050").Group }

func (c *svc050) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC050")}
	}
	cf, ok := configBySchema(ctx.Collector, "minio-env")
	if !ok {
		return []model.Finding{notAssessed("SVC050")}
	}

	if cf.Values["root-creds.default"] == "true" {
		f := catalog.Get("SVC050").Finding()
		f.Resource = "minio"
		f.Evidence = "MINIO_ROOT_USER and MINIO_ROOT_PASSWORD match the well-known minioadmin defaults"
		f.Metadata = map[string]string{"port": "9000"}
		f.Fix = model.Fix{
			Summary: "Set MINIO_ROOT_USER and MINIO_ROOT_PASSWORD to unique non-default values in the MinIO environment file.",
			Diff:    "MINIO_ROOT_USER=<unique-user>\nMINIO_ROOT_PASSWORD=<strong-password>",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC050").Pass("MinIO root credentials are not the default.")}
}
