package host

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst010{}) }

type hst010 struct{}

func (c *hst010) ID() string              { return catalog.Get("HST010").ID }
func (c *hst010) Title() string           { return catalog.Get("HST010").Title }
func (c *hst010) Group() model.CheckGroup { return catalog.Get("HST010").Group }

func (c *hst010) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST010")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("HST010")}
	}
	pkg := ctx.Collector.Packages
	if pkg.SecurityUpdatesPending == 0 {
		return []model.Finding{catalog.Get("HST010").Pass("No pending security updates.")}
	}
	f := catalog.Get("HST010").Finding()
	if pkg.DistroEOL || pkg.SecurityUpdatesPending > 20 {
		f.Severity = model.SeverityCritical
	}
	f.Resource = "apt"
	f.Evidence = fmt.Sprintf("%d security update(s) pending", pkg.SecurityUpdatesPending)
	f.Fix = model.Fix{
		Summary:  "Apply pending security updates immediately.",
		Commands: []string{"apt-get update && apt-get upgrade -y"},
	}
	return []model.Finding{f}
}
