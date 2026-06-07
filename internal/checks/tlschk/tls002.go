package tlschk

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&tls002{}) }

type tls002 struct{}

func (c *tls002) ID() string              { return catalog.Get("TLS002").ID }
func (c *tls002) Title() string           { return catalog.Get("TLS002").Title }
func (c *tls002) Group() model.CheckGroup { return catalog.Get("TLS002").Group }

func (c *tls002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}
	if len(ctx.Probe.Certificates) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, cert := range ctx.Probe.Certificates {
		if cert.Expired {
			f := catalog.Get("TLS002").Finding()
			f.Resource = cert.Endpoint
			f.Evidence = fmt.Sprintf(
				"Certificate expired on %s (%d days ago).",
				cert.NotAfter.Format("2006-01-02"),
				-cert.DaysUntilExpiry,
			)
			f.Fix = model.Fix{
				Summary: "Renew the TLS certificate. If using Let's Encrypt, check that certbot/acme.sh renewal is running correctly.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("TLS002").Pass("No expired TLS certificates found on public endpoints.")}
	}
	return findings
}
