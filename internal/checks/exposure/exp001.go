// Package exposure implements network-exposure checks (EXP*).
package exposure

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&exp001{}) }

type exp001 struct{}

func (c *exp001) ID() string              { return catalog.Get("EXP001").ID }
func (c *exp001) Title() string           { return catalog.Get("EXP001").Title }
func (c *exp001) Group() model.CheckGroup { return catalog.Get("EXP001").Group }

func (c *exp001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}

	var findings []model.Finding

	for port, pp := range ctx.Probe.Reachable {
		if !pp.Open {
			continue
		}
		if !intel.IsSensitivePort(port) {
			continue
		}
		if ctx.Intended[port] {
			continue
		}

		info, _ := intel.LookupPort(port)
		vantage := ctx.Probe.VantagePoint
		if vantage == "" {
			vantage = "the internet"
		}

		// Find the owning compose service.
		svcName := owningService(ctx.Stack, port)

		f := catalog.Get("EXP001").Finding()
		f.Service = svcName
		f.Resource = fmt.Sprintf("port %d", port)
		f.Evidence = fmt.Sprintf("%s is reachable on port %d from %s", info.Service, port, vantage)
		f.Fix = model.Fix{
			Summary: "Bind to 127.0.0.1 and reach via reverse proxy or SSH tunnel",
			Diff: fmt.Sprintf(
				"ports:\n  - \"%d:%d\"  ->  \"127.0.0.1:%d:%d\"",
				port, port, port, port,
			),
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("EXP001").Pass("No sensitive services are reachable from the internet.")}
	}
	return findings
}

// owningService returns the name of the compose service that publishes the
// given host port, or "" if none is found.
func owningService(stack *model.Stack, hostPort int) string {
	if stack == nil {
		return ""
	}
	for _, svc := range stack.Services {
		for _, pm := range svc.Ports {
			if pm.HostPort == hostPort {
				return svc.Name
			}
		}
	}
	return ""
}
