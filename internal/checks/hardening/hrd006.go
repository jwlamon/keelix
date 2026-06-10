package hardening

import (
	"fmt"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hrd006{}) }

type hrd006 struct{}

func (c *hrd006) ID() string              { return catalog.Get("HRD006").ID }
func (c *hrd006) Title() string           { return catalog.Get("HRD006").Title }
func (c *hrd006) Group() model.CheckGroup { return catalog.Get("HRD006").Group }

// hasNoNewPrivileges returns true if the security_opt list contains an entry
// containing "no-new-privileges".
func hasNoNewPrivileges(opts []string) bool {
	for _, o := range opts {
		if strings.Contains(o, "no-new-privileges") {
			return true
		}
	}
	return false
}

func (c *hrd006) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessedNoServices("HRD006")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		if hasNoNewPrivileges(svc.SecurityOpt) {
			continue
		}
		f := catalog.Get("HRD006").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("container %s", svc.Name)
		f.Evidence = fmt.Sprintf("service %q is missing no-new-privileges in security_opt", svc.Name)
		f.Fix = model.Fix{
			Summary: `Add security_opt: ["no-new-privileges:true"] to prevent privilege escalation via setuid binaries.`,
			Diff:    "+    security_opt:\n+      - no-new-privileges:true",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("HRD006").Pass("All containers have no-new-privileges set.")}
	}
	return findings
}
