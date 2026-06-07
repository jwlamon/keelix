// Package dns implements DNS checks (DNS*).
package dns

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&dns001{}) }

type dns001 struct{}

func (c *dns001) ID() string              { return catalog.Get("DNS001").ID }
func (c *dns001) Title() string           { return catalog.Get("DNS001").Title }
func (c *dns001) Group() model.CheckGroup { return catalog.Get("DNS001").Group }

func (c *dns001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}

	var findings []model.Finding
	for _, rec := range ctx.Probe.DNSRecords {
		if rec.Wildcard {
			f := catalog.Get("DNS001").Finding()
			f.Resource = rec.Name
			f.Evidence = "Wildcard DNS record resolves all subdomains to this host."
			f.Fix = model.Fix{
				Summary: "Replace the wildcard record with explicit DNS entries for each intended subdomain.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("DNS001").Pass("No wildcard DNS records found pointing at this host.")}
	}
	return findings
}
