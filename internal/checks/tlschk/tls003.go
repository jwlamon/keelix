package tlschk

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&tls003{}) }

type tls003 struct{}

func (c *tls003) ID() string              { return catalog.Get("TLS003").ID }
func (c *tls003) Title() string           { return catalog.Get("TLS003").Title }
func (c *tls003) Group() model.CheckGroup { return catalog.Get("TLS003").Group }

func (c *tls003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}
	if len(ctx.Probe.Certificates) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, cert := range ctx.Probe.Certificates {
		if cert.SelfSigned {
			f := catalog.Get("TLS003").Finding()
			f.Resource = cert.Endpoint
			f.Evidence = "Certificate is self-signed (not issued by a trusted CA)."
			f.Fix = model.Fix{
				Summary: "Replace the self-signed certificate with a CA-issued certificate (e.g. Let's Encrypt via Certbot or the reverse proxy's built-in ACME client).",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("TLS003").Pass("No self-signed certificates found on public endpoints.")}
	}
	return findings
}
