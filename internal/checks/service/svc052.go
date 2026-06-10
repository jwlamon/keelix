package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc052{}) }

type svc052 struct{}

func (c *svc052) ID() string              { return catalog.Get("SVC052").ID }
func (c *svc052) Title() string           { return catalog.Get("SVC052").Title }
func (c *svc052) Group() model.CheckGroup { return catalog.Get("SVC052").Group }

func (c *svc052) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC052")}
	}
	cf, ok := configBySchema(ctx.Collector, "syncthing-config")
	if !ok {
		return []model.Finding{notAssessed("SVC052")}
	}
	if cf.Values["gui.auth"] != "false" {
		return []model.Finding{catalog.Get("SVC052").Pass("Syncthing GUI authentication is configured.")}
	}
	f := catalog.Get("SVC052").Finding()
	f.Resource = "syncthing GUI"
	f.Evidence = "gui.auth=false (no username/password configured)"
	f.Metadata = map[string]string{"port": "8384"}
	f.Fix = model.Fix{
		Summary: "Set a GUI password in Syncthing: Actions → Settings → GUI → set GUI Authentication User and GUI Authentication Password.",
		DocURL:  "https://docs.syncthing.net/users/guilisten.html#gui-authentication",
	}
	return []model.Finding{f}
}
