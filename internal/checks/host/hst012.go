package host

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst012{}) }

type hst012 struct{}

func (c *hst012) ID() string              { return catalog.Get("HST012").ID }
func (c *hst012) Title() string           { return catalog.Get("HST012").Title }
func (c *hst012) Group() model.CheckGroup { return catalog.Get("HST012").Group }

func (c *hst012) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST012")}
	}
	if !ctx.Collector.Packages.RebootRequired {
		return []model.Finding{catalog.Get("HST012").Pass("No reboot required.")}
	}
	f := catalog.Get("HST012").Finding()
	f.Resource = "host"
	f.Evidence = "/var/run/reboot-required exists"
	f.Fix = model.Fix{
		Summary:  "Reboot the host to apply kernel/library updates.",
		Commands: []string{"shutdown -r now"},
	}
	return []model.Finding{f}
}
