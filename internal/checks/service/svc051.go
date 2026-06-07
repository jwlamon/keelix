package service

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&svc051{}) }

type svc051 struct{}

func (c *svc051) ID() string              { return catalog.Get("SVC051").ID }
func (c *svc051) Title() string           { return catalog.Get("SVC051").Title }
func (c *svc051) Group() model.CheckGroup { return catalog.Get("SVC051").Group }

func (c *svc051) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC051")}
	}
	cf, ok := configBySchema(ctx.Collector, "mosquitto-conf")
	if !ok {
		return []model.Finding{notAssessed("SVC051")}
	}

	if cf.Values["allow_anonymous"] == "true" {
		f := catalog.Get("SVC051").Finding()
		f.Resource = "mosquitto"
		f.Evidence = "allow_anonymous true"
		f.Metadata = map[string]string{"port": "1883"}
		f.Fix = model.Fix{
			Summary: "Set allow_anonymous false in mosquitto.conf and configure password_file or plugin-based authentication.",
			Diff:    "allow_anonymous false\npassword_file /etc/mosquitto/passwd",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC051").Pass("Mosquitto anonymous access is disabled.")}
}
