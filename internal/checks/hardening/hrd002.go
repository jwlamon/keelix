package hardening

import (
	"fmt"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd002{}) }

type hrd002 struct{}

func (c *hrd002) ID() string              { return catalog.Get("HRD002").ID }
func (c *hrd002) Title() string           { return catalog.Get("HRD002").Title }
func (c *hrd002) Group() model.CheckGroup { return catalog.Get("HRD002").Group }

// criticalCaps are capabilities that escalate the finding severity to Critical.
var criticalCaps = map[string]bool{
	"ALL":        true,
	"SYS_ADMIN":  true,
	"SYS_MODULE": true,
}

// isCriticalCap returns true if the normalized capability name warrants Critical severity.
func isCriticalCap(cap string) bool {
	normalized := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))
	return criticalCaps[normalized]
}

func (c *hrd002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD002")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		for _, cap := range svc.CapAdd {
			reason, ok := intel.DangerousCap(cap)
			if !ok {
				continue
			}
			f := catalog.Get("HRD002").Finding()
			f.Service = svc.Name
			f.Resource = fmt.Sprintf("capability %s", cap)
			f.Evidence = fmt.Sprintf("service %q adds capability %s: %s", svc.Name, cap, reason)
			f.Fix = model.Fix{
				Summary: fmt.Sprintf("Drop the %s capability from cap_add; use the minimum required set.", cap),
				Diff:    fmt.Sprintf("- - %s", cap),
			}
			if isCriticalCap(cap) {
				f.Severity = model.SeverityCritical
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD002").Pass("No dangerous Linux capabilities added to any container.")}
	}
	return findings
}
