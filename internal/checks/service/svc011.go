package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc011{}) }

type svc011 struct{}

func (c *svc011) ID() string              { return catalog.Get("SVC011").ID }
func (c *svc011) Title() string           { return catalog.Get("SVC011").Title }
func (c *svc011) Group() model.CheckGroup { return catalog.Get("SVC011").Group }

func (c *svc011) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC011")}
	}
	cf, ok := configBySchema(ctx.Collector, "qbittorrent-conf")
	if !ok {
		return []model.Finding{notAssessed("SVC011")}
	}
	if cf.Values["webui.auth"] != "false" {
		return []model.Finding{catalog.Get("SVC011").Pass("qBittorrent WebUI authentication is enabled.")}
	}
	f := catalog.Get("SVC011").Finding()
	f.Resource = "qbittorrent WebUI"
	f.Evidence = "webui.auth=false"
	f.Metadata = map[string]string{"port": "8080"}
	f.Fix = model.Fix{
		Summary: "Enable WebUI authentication in qBittorrent: Tools → Options → Web UI → enable 'Bypass authentication for clients on localhost' if needed, but set a username and password.",
		Diff:    "WebUI\\Password_PBKDF2=... (set a non-empty password via the qBittorrent UI)",
	}
	return []model.Finding{f}
}
