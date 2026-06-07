package host

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst011{}) }

type hst011 struct{}

func (c *hst011) ID() string              { return catalog.Get("HST011").ID }
func (c *hst011) Title() string           { return catalog.Get("HST011").Title }
func (c *hst011) Group() model.CheckGroup { return catalog.Get("HST011").Group }

func (c *hst011) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST011")}
	}
	if !ctx.Collector.Packages.DistroEOL {
		return []model.Finding{catalog.Get("HST011").Pass("Distro is within support lifetime.")}
	}
	f := catalog.Get("HST011").Finding()
	f.Resource = ctx.Collector.Platform.Distro + " " + ctx.Collector.Platform.Version
	f.Evidence = "Distro has reached end-of-life; security updates are no longer provided by the vendor"
	f.Fix = model.Fix{
		Summary: "Upgrade to a supported distro release or migrate to a supported LTS version.",
	}
	return []model.Finding{f}
}
