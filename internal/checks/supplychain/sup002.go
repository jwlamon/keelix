package supplychain

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&sup002{}) }

// knownCompromised is the set of image bases on the compromised feed.
// It is empty by default to prevent false positives.
var knownCompromised = map[string]bool{}

// SetCompromisedFeed loads a feed of known-compromised image base names,
// replacing the current feed. Pass an empty slice to clear the feed.
func SetCompromisedFeed(images []string) {
	m := make(map[string]bool, len(images))
	for _, img := range images {
		m[intel.ImageBase(img)] = true
	}
	knownCompromised = m
}

type sup002 struct{}

func (c *sup002) ID() string              { return catalog.Get("SUP002").ID }
func (c *sup002) Title() string           { return catalog.Get("SUP002").Title }
func (c *sup002) Group() model.CheckGroup { return catalog.Get("SUP002").Group }

func (c *sup002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SUP002")}
	}

	// With an empty feed the check always passes.
	if len(knownCompromised) == 0 {
		return []model.Finding{catalog.Get("SUP002").Pass("No images matched the known-compromised feed.")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if svc.Image == "" {
			continue
		}
		base := intel.ImageBase(svc.Image)
		if !knownCompromised[base] {
			continue
		}
		f := catalog.Get("SUP002").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("image %s", svc.Image)
		f.Evidence = fmt.Sprintf("image %q (base: %q) is listed on the known-compromised feed", svc.Image, base)
		f.Fix = model.Fix{
			Summary: "Stop using this image immediately, remove any containers running it, and investigate for signs of compromise.",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SUP002").Pass("No images matched the known-compromised feed.")}
	}
	return findings
}
