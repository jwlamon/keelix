// Package firewall implements Docker/firewall-bypass checks (FW*).
package firewall

import (
	"fmt"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&fw001{}) }

type fw001 struct{}

func (c *fw001) ID() string              { return catalog.Get("FW001").ID }
func (c *fw001) Title() string           { return catalog.Get("FW001").Title }
func (c *fw001) Group() model.CheckGroup { return catalog.Get("FW001").Group }

func (c *fw001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack.Firewall == nil {
		return nil
	}

	engine := string(ctx.Stack.Firewall.Engine)
	if engine == "" {
		engine = "the firewall"
	}

	var findings []model.Finding

	for _, svc := range ctx.Stack.Services {
		for _, pm := range svc.Ports {
			if !pm.PublishedToAllInterfaces() || pm.HostPort == 0 {
				continue
			}
			if !ctx.Stack.Firewall.Denies(pm.HostPort) {
				continue
			}

			evidence := fmt.Sprintf(
				"Compose publishes %d but %s has `deny %d` — Docker writes its iptables rules before %s, so the port is reachable anyway",
				pm.HostPort, engine, pm.HostPort, engine,
			)
			if ctx.Probe != nil && ctx.Probe.IsReachable(pm.HostPort) {
				evidence += " (confirmed reachable from outside)"
			}

			f := catalog.Get("FW001").Finding()
			f.Service = svc.Name
			f.Resource = fmt.Sprintf("port %d", pm.HostPort)
			f.Evidence = evidence
			f.Fix = model.Fix{
				Summary: fmt.Sprintf("Bind port %d to 127.0.0.1 in Compose, or add a DOCKER-USER iptables rule to block it", pm.HostPort),
				Diff: fmt.Sprintf(
					"ports:\n  - \"%d:%d\"  ->  \"127.0.0.1:%d:%d\"",
					pm.HostPort, pm.ContainerPort, pm.HostPort, pm.ContainerPort,
				),
				Commands: []string{
					fmt.Sprintf(
						"iptables -I DOCKER-USER -p tcp --dport %d -j DROP",
						pm.HostPort,
					),
				},
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("FW001").Pass("No published ports are blocked by the host firewall in a way Docker would bypass.")}
	}
	return findings
}
