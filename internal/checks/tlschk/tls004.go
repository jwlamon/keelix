package tlschk

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&tls004{}) }

type tls004 struct{}

func (c *tls004) ID() string              { return catalog.Get("TLS004").ID }
func (c *tls004) Title() string           { return catalog.Get("TLS004").Title }
func (c *tls004) Group() model.CheckGroup { return catalog.Get("TLS004").Group }

// weakTLSVersion reports whether the TLS version string is a known weak version.
func weakTLSVersion(v string) bool {
	return v == "TLS 1.0" || v == "TLS 1.1"
}

func (c *tls004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}
	if len(ctx.Probe.Certificates) == 0 {
		return nil
	}

	var findings []model.Finding
	for _, cert := range ctx.Probe.Certificates {
		if cert.WeakCipher || weakTLSVersion(cert.TLSVersion) {
			f := catalog.Get("TLS004").Finding()
			f.Resource = cert.Endpoint
			f.Evidence = fmt.Sprintf(
				"TLS version: %s; weak cipher: %v (cipher: %s).",
				cert.TLSVersion, cert.WeakCipher, cert.CipherName,
			)
			f.Fix = model.Fix{
				Summary: "Configure the reverse proxy to require TLS 1.2 or higher and disable weak cipher suites.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("TLS004").Pass("No weak TLS versions or cipher suites found on public endpoints.")}
	}
	return findings
}
