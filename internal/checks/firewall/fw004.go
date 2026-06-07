package firewall

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&fw004{}) }

type fw004 struct{}

func (c *fw004) ID() string              { return catalog.Get("FW004").ID }
func (c *fw004) Title() string           { return catalog.Get("FW004").Title }
func (c *fw004) Group() model.CheckGroup { return catalog.Get("FW004").Group }

func (c *fw004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Firewall == nil {
		return nil
	}

	// Only applicable when at least one service publishes a port to all interfaces.
	hasPublicPort := false
	for _, svc := range ctx.Stack.Services {
		for _, pm := range svc.Ports {
			if pm.PublishedToAllInterfaces() && pm.HostPort != 0 {
				hasPublicPort = true
				break
			}
		}
		if hasPublicPort {
			break
		}
	}
	if !hasPublicPort {
		return nil
	}

	if ctx.Stack.Firewall.HasDockerUserChain {
		return []model.Finding{catalog.Get("FW004").Pass("A DOCKER-USER firewall chain is present to restrict published ports.")}
	}

	f := catalog.Get("FW004").Finding()
	f.Evidence = "No DOCKER-USER iptables chain rule was found; Docker-published ports bypass the host firewall"
	f.Fix = model.Fix{
		Summary: "Add DOCKER-USER iptables rules to restrict which external addresses can reach published container ports",
		Commands: []string{
			"iptables -N DOCKER-USER 2>/dev/null || true",
			"iptables -I DOCKER-USER -i eth0 -j DROP",
		},
	}
	return []model.Finding{f}
}
