package exposure

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&exp002{}) }

type exp002 struct{}

func (c *exp002) ID() string              { return catalog.Get("EXP002").ID }
func (c *exp002) Title() string           { return catalog.Get("EXP002").Title }
func (c *exp002) Group() model.CheckGroup { return catalog.Get("EXP002").Group }

func (c *exp002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Probe == nil {
		return nil
	}

	// Build the set of declared host ports published to all interfaces.
	declaredPorts := declaredPublicHostPorts(ctx.Stack)

	vantage := ctx.Probe.VantagePoint
	if vantage == "" {
		vantage = "the internet"
	}

	var findings []model.Finding

	for port, pp := range ctx.Probe.Reachable {
		if !pp.Open {
			continue
		}
		if declaredPorts[port] {
			continue // declared in Compose
		}
		if ctx.Intended[port] {
			continue
		}
		if intel.IsSensitivePort(port) {
			continue // covered by EXP001
		}
		if port == 80 || port == 443 {
			continue
		}

		f := catalog.Get("EXP002").Finding()
		f.Resource = fmt.Sprintf("port %d", port)
		f.Evidence = fmt.Sprintf("port %d is reachable from %s but is not declared in Compose", port, vantage)
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("EXP002").Pass("No undeclared ports are reachable from the internet.")}
	}
	return findings
}

// declaredPublicHostPorts returns the set of host ports that are published to
// all interfaces (not loopback-bound) in the stack.
func declaredPublicHostPorts(stack *model.Stack) map[int]bool {
	result := make(map[int]bool)
	if stack == nil {
		return result
	}
	for _, svc := range stack.Services {
		for _, pm := range svc.Ports {
			if pm.PublishedToAllInterfaces() && pm.HostPort != 0 {
				result[pm.HostPort] = true
			}
		}
	}
	return result
}
