// Package supplychain implements supply-chain checks (SUP*).
package supplychain

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&sup001{}) }

type sup001 struct{}

func (c *sup001) ID() string              { return catalog.Get("SUP001").ID }
func (c *sup001) Title() string           { return catalog.Get("SUP001").Title }
func (c *sup001) Group() model.CheckGroup { return catalog.Get("SUP001").Group }

func (c *sup001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SUP001")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if svc.Image == "" {
			continue
		}
		if intel.HasDigest(svc.Image) {
			continue
		}
		f := catalog.Get("SUP001").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("image %s", svc.Image)
		f.Evidence = fmt.Sprintf("image %q does not include an @sha256 digest", svc.Image)
		f.Fix = model.Fix{
			Summary: "Pin the image to a specific digest to guarantee reproducible deployments.",
			Diff:    fmt.Sprintf("image: %s  ->  %s@sha256:<digest>", svc.Image, intel.ImageBase(svc.Image)),
			DocURL:  "https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SUP001").Pass("All images are pinned to a digest (or no images present).")}
	}
	return findings
}
