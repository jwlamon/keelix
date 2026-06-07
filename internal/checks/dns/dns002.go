package dns

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&dns002{}) }

type dns002 struct{}

func (c *dns002) ID() string              { return catalog.Get("DNS002").ID }
func (c *dns002) Title() string           { return catalog.Get("DNS002").Title }
func (c *dns002) Group() model.CheckGroup { return catalog.Get("DNS002").Group }

func (c *dns002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}

	var findings []model.Finding
	for _, rec := range ctx.Probe.DNSRecords {
		if rec.Dangling {
			f := catalog.Get("DNS002").Finding()
			f.Resource = fmt.Sprintf("%s -> %s", rec.Name, rec.Value)
			f.Evidence = fmt.Sprintf(
				"DNS record %s (%s) points to %q which does not resolve or is unclaimed.",
				rec.Name, rec.Type, rec.Value,
			)
			f.Fix = model.Fix{
				Summary: "Remove or update the dangling DNS record. If the target is an external service, claim it or delete the record to prevent subdomain takeover.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("DNS002").Pass("No dangling DNS records found.")}
	}
	return findings
}
