// Package secrets implements secrets-related checks (SEC*).
package secrets

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&sec001{}) }

type sec001 struct{}

func (c *sec001) ID() string              { return catalog.Get("SEC001").ID }
func (c *sec001) Title() string           { return catalog.Get("SEC001").Title }
func (c *sec001) Group() model.CheckGroup { return catalog.Get("SEC001").Group }

// isLiteral returns true if the value is non-empty and not a ${...} or $... reference.
func isLiteral(v string) bool {
	if v == "" {
		return false
	}
	return !strings.HasPrefix(v, "${") && !strings.HasPrefix(v, "$")
}

func (c *sec001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SEC001")}
	}

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		for name, val := range svc.Environment {
			if !intel.IsSecretEnvName(name) {
				continue
			}
			if !isLiteral(val) {
				continue
			}
			f := catalog.Get("SEC001").Finding()
			f.Service = svc.Name
			f.Resource = name
			f.Evidence = fmt.Sprintf("%s is set to a literal value in Compose", name)
			f.Fix = model.Fix{
				Summary: "Move to Docker secrets or a mounted secret file, or use a ${ENV_VAR} reference.",
				Diff:    fmt.Sprintf("environment:\n  %s: ${%s}  # reference from .env or Docker secret", name, name),
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SEC001").Pass("No secrets found in plaintext in Compose configuration.")}
	}
	return findings
}
