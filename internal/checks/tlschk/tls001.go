// Package tlschk implements TLS/certificate checks (TLS*).
package tlschk

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&tls001{}) }

type tls001 struct{}

func (c *tls001) ID() string              { return catalog.Get("TLS001").ID }
func (c *tls001) Title() string           { return catalog.Get("TLS001").Title }
func (c *tls001) Group() model.CheckGroup { return catalog.Get("TLS001").Group }

func (c *tls001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}

	port80 := ctx.Probe.Reachable[80]
	port443 := ctx.Probe.Reachable[443]

	// If port 80 is not open, nothing to flag here.
	if !port80.Open {
		return nil
	}

	// If port 443 is reachable, HTTPS exists — pass.
	if port443.Open {
		return []model.Finding{catalog.Get("TLS001").Pass("HTTPS (port 443) is reachable.")}
	}

	// Port 80 open, port 443 not reachable: flag as no HTTPS.
	f := catalog.Get("TLS001").Finding()
	f.Evidence = "Port 80 (HTTP) is reachable from outside but port 443 (HTTPS) is not."
	f.Fix = model.Fix{
		Summary: "Terminate TLS at the reverse proxy and redirect HTTP to HTTPS.",
	}
	return []model.Finding{f}
}
