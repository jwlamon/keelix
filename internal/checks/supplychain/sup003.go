package supplychain

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/threatfeed"
)

func init() { model.Register(&sup003{}) }

type sup003 struct{}

func (c *sup003) ID() string              { return catalog.Get("SUP003").ID }
func (c *sup003) Title() string           { return catalog.Get("SUP003").Title }
func (c *sup003) Group() model.CheckGroup { return catalog.Get("SUP003").Group }

func (c *sup003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SUP003")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if svc.Image == "" {
			continue
		}
		cves, ok := intel.ImageCVEs(svc.Image)
		if !ok {
			continue
		}
		// Collect KEV-listed CVEs for this image.
		var kev []string
		for _, cve := range cves {
			if threatfeed.KEVListed(cve) {
				kev = append(kev, cve)
			}
		}
		if len(kev) == 0 {
			continue
		}
		// Rank KEV CVEs by EPSS bucket descending so the representative "worst"
		// CVE carries the highest exploitation-probability signal. Tie-break
		// lexicographically (ascending) for determinism when buckets are equal.
		sort.Slice(kev, func(i, j int) bool {
			bi, _ := threatfeed.EPSSBucket(kev[i])
			bj, _ := threatfeed.EPSSBucket(kev[j])
			if bi != bj {
				return bi > bj // descending EPSS
			}
			return kev[i] < kev[j] // ascending lex tie-break
		})
		worst := kev[0]

		f := catalog.Get("SUP003").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("image %s", svc.Image)
		f.Evidence = fmt.Sprintf("image %q is affected by known-exploited CVE %s (CISA KEV)", svc.Image, worst)
		f.Confidence = model.ConfidenceHigh
		f.Metadata = map[string]string{"cve": worst}
		if port, ok := mostExposedHostPort(svc); ok {
			// Stamp the port so correlate.Classify resolves a real ExposureClass;
			// applyKEVFatal then escalates KEV+routable to Fatal → RED cap.
			f.Metadata["port"] = strconv.Itoa(port)
		}
		f.Fix = model.Fix{
			Summary: fmt.Sprintf("Update %s to a version that patches %s, or pin to a fixed digest. Known-exploited CVEs are actively used in the wild — patch immediately.", svc.Image, worst),
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SUP003").Pass("No images mapped to a known-exploited (KEV) CVE.")}
	}
	return findings
}

// mostExposedHostPort returns the highest published host port for a service that
// is bound to all interfaces (the most-exposed candidate), preferring such a
// port over a loopback-only one. ok is false when the service publishes nothing.
func mostExposedHostPort(svc *model.Service) (int, bool) {
	best := 0
	found := false
	bestPublic := false
	for _, pm := range svc.Ports {
		if pm.HostPort == 0 {
			continue
		}
		public := pm.PublishedToAllInterfaces()
		// Prefer a public binding; among same publicness, take the highest port.
		if !found || (public && !bestPublic) || (public == bestPublic && pm.HostPort > best) {
			best = pm.HostPort
			bestPublic = public
			found = true
		}
	}
	return best, found
}
