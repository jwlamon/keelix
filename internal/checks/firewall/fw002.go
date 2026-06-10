package firewall

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&fw002{}) }

type fw002 struct{}

func (c *fw002) ID() string              { return catalog.Get("FW002").ID }
func (c *fw002) Title() string           { return catalog.Get("FW002").Title }
func (c *fw002) Group() model.CheckGroup { return catalog.Get("FW002").Group }

func (c *fw002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("FW002")}
	}

	var findings []model.Finding

	for _, svc := range ctx.Stack.Services {
		for _, pm := range svc.Ports {
			if !pm.PublishedToAllInterfaces() {
				continue
			}
			// Check host port first; fall back to container port.
			checkPort := pm.HostPort
			if checkPort == 0 {
				checkPort = pm.ContainerPort
			}
			if !intel.IsSensitivePort(checkPort) {
				continue
			}
			if ctx.Intended[checkPort] {
				continue
			}

			info, _ := intel.LookupPort(checkPort)
			f := catalog.Get("FW002").Finding()
			f.Service = svc.Name
			f.Resource = fmt.Sprintf("port %d", checkPort)
			f.Evidence = fmt.Sprintf("%s (port %d) is bound to all interfaces (0.0.0.0)", info.Service, checkPort)
			f.Fix = model.Fix{
				Summary: fmt.Sprintf("Bind port %d to 127.0.0.1 so it is not reachable from external interfaces", checkPort),
				Diff: fmt.Sprintf(
					"ports:\n  - \"%d:%d\"  ->  \"127.0.0.1:%d:%d\"",
					checkPort, pm.ContainerPort, checkPort, pm.ContainerPort,
				),
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("FW002").Pass("No sensitive ports are bound to all interfaces.")}
	}
	return findings
}
