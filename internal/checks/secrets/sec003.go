package secrets

import (
	"fmt"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&sec003{}) }

type sec003 struct{}

func (c *sec003) ID() string              { return catalog.Get("SEC003").ID }
func (c *sec003) Title() string           { return catalog.Get("SEC003").Title }
func (c *sec003) Group() model.CheckGroup { return catalog.Get("SEC003").Group }

// isPasswordName returns true if the env var name contains PASSWORD, PASS, or PWD (case-insensitive).
func isPasswordName(name string) bool {
	upper := strings.ToUpper(name)
	return strings.Contains(upper, "PASSWORD") ||
		strings.Contains(upper, "PASS") ||
		strings.Contains(upper, "PWD")
}

// redactedDescription returns a non-revealing description of a weak password value.
func redactedDescription(val string) string {
	if val == "" {
		return "empty"
	}
	if len(val) < 8 {
		return fmt.Sprintf("too short (%d chars)", len(val))
	}
	return "common default password"
}

func (c *sec003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SEC003")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		for name, val := range svc.Environment {
			if !isPasswordName(name) {
				continue
			}
			if !isLiteral(val) {
				continue
			}
			if !intel.IsWeakPassword(val) {
				continue
			}
			f := catalog.Get("SEC003").Finding()
			f.Service = svc.Name
			f.Resource = name
			f.Evidence = fmt.Sprintf("%s has a weak password (%s)", name, redactedDescription(val))
			f.Fix = model.Fix{
				Summary: "Set a strong, unique password of at least 16 characters and store it in a Docker secret or external secrets manager.",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SEC003").Pass("No weak or default passwords detected.")}
	}
	return findings
}
