package supplychain

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/threatfeed"
)

func init() { model.Register(&sup004{}) }

// sup004EPSSBucketThreshold is the integer bucket threshold (inclusive) at or
// above which a non-KEV CVE triggers SUP004. At quantization resolution of
// 1/200 the boundary "EPSS percentile > 0.90" maps to bucket 181: bucket 180
// decodes to exactly 0.90 (180/200), so comparing in float space would treat
// that as meeting the threshold — a false positive for CVEs whose true EPSS
// is just below 0.90. Comparing in integer bucket space avoids this.
const sup004EPSSBucketThreshold = uint8(181)

type sup004 struct{}

func (c *sup004) ID() string              { return catalog.Get("SUP004").ID }
func (c *sup004) Title() string           { return catalog.Get("SUP004").Title }
func (c *sup004) Group() model.CheckGroup { return catalog.Get("SUP004").Group }

func (c *sup004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SUP004")}
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
		// Find the worst non-KEV CVE whose EPSS bucket is at or above the
		// threshold (bucket 181 = first bucket strictly above 0.90). Comparing
		// in integer bucket space avoids floating-point rounding artifacts at
		// the 0.90 boundary (see sup004EPSSBucketThreshold).
		worst := ""
		worstBucket := uint8(0)
		for _, cve := range cves {
			if threatfeed.KEVListed(cve) {
				continue // KEV CVEs are SUP003's domain, not SUP004's.
			}
			b, present := threatfeed.EPSSBucket(cve)
			if !present || b < sup004EPSSBucketThreshold {
				continue
			}
			// Higher bucket wins; ties broken by lower CVE id for determinism.
			if b > worstBucket || (b == worstBucket && (worst == "" || cve < worst)) {
				worst = cve
				worstBucket = b
			}
		}
		if worst == "" {
			continue
		}

		worstP := float64(worstBucket) / 200.0
		f := catalog.Get("SUP004").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("image %s", svc.Image)
		f.Evidence = fmt.Sprintf("image %q is affected by high-EPSS CVE %s (percentile %.2f, not on CISA KEV)", svc.Image, worst, worstP)
		f.Confidence = model.ConfidenceMedium
		f.Metadata = map[string]string{"cve": worst}
		f.Fix = model.Fix{
			Summary: fmt.Sprintf("Plan an update for %s to patch %s. Its EPSS percentile is high (%.2f) — exploitation is likely; patch soon.", svc.Image, worst, worstP),
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SUP004").Pass("No images mapped to a high-EPSS CVE.")}
	}
	return findings
}
