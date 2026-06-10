package hardening

import (
	"fmt"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd008{}) }

type hrd008 struct{}

func (c *hrd008) ID() string              { return catalog.Get("HRD008").ID }
func (c *hrd008) Title() string           { return catalog.Get("HRD008").Title }
func (c *hrd008) Group() model.CheckGroup { return catalog.Get("HRD008").Group }

func (c *hrd008) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD008")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		// Skip locally-built services (no image reference).
		if svc.Image == "" {
			continue
		}
		// Skip images already pinned with a content digest.
		if intel.HasDigest(svc.Image) {
			continue
		}
		tag := intel.ImageTag(svc.Image)
		if tag != "" && !strings.EqualFold(tag, "latest") {
			// Explicit non-latest tag without digest — passes this check.
			continue
		}
		// tag == "" (untagged) or == "latest" (case-insensitive).
		f := catalog.Get("HRD008").Finding()
		f.Service = svc.Name
		f.Resource = svc.Image
		if tag == "" {
			f.Evidence = fmt.Sprintf("service %q uses image %q with no tag (implicitly :latest)", svc.Name, svc.Image)
		} else {
			f.Evidence = fmt.Sprintf("service %q uses image %q with mutable :latest tag", svc.Name, svc.Image)
		}
		f.Fix = model.Fix{
			Summary: "Pin the image to an explicit version tag and ideally an @sha256 digest for reproducible builds.",
			Diff:    fmt.Sprintf("-    image: %s\n+    image: %s:<version>@sha256:<digest>", svc.Image, intel.ImageBase(svc.Image)),
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD008").Pass("All images are pinned to an explicit version tag.")}
	}
	return findings
}
