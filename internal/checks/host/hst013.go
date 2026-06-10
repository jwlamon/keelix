package host

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst013{}) }

type hst013 struct{}

func (c *hst013) ID() string              { return catalog.Get("HST013").ID }
func (c *hst013) Title() string           { return catalog.Get("HST013").Title }
func (c *hst013) Group() model.CheckGroup { return catalog.Get("HST013").Group }

func (c *hst013) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST013")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("HST013")}
	}
	cf, ok := configBySchema(ctx.Collector, "apt-periodic")
	if !ok {
		return []model.Finding{notAssessed("HST013")}
	}
	if cf.Values["unattended_upgrade"] == "1" {
		return []model.Finding{catalog.Get("HST013").Pass("Unattended upgrades are enabled.")}
	}
	f := catalog.Get("HST013").Finding()
	f.Resource = "apt-periodic"
	f.Evidence = "Unattended-Upgrade not set to 1 in apt periodic config"
	f.Fix = model.Fix{
		Summary: "Enable unattended-upgrades for automatic security patch application.",
		Commands: []string{
			"apt-get install -y unattended-upgrades",
			"dpkg-reconfigure -plow unattended-upgrades",
		},
	}
	return []model.Finding{f}
}
