package secrets

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&sec004{}) }

type sec004 struct{}

func (c *sec004) ID() string              { return catalog.Get("SEC004").ID }
func (c *sec004) Title() string           { return catalog.Get("SEC004").Title }
func (c *sec004) Group() model.CheckGroup { return catalog.Get("SEC004").Group }

func (c *sec004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("SEC004")}
	}

	// If the stack already uses compose secrets, this check is satisfied.
	useDockerSecrets := len(ctx.Stack.Secrets) > 0

	var findings []model.Finding
	for _, svc := range ctx.Stack.Services {
		hasSecretLiteral := false
		for name, val := range svc.Environment {
			if intel.IsSecretEnvName(name) && isLiteral(val) {
				hasSecretLiteral = true
				break
			}
		}
		if !hasSecretLiteral {
			continue
		}
		if useDockerSecrets {
			continue
		}
		f := catalog.Get("SEC004").Finding()
		f.Service = svc.Name
		f.Evidence = fmt.Sprintf("service %q passes secrets via environment variables and the stack does not use compose secrets:", svc.Name)
		f.Fix = model.Fix{
			Summary: "Migrate secrets to Docker secrets (secrets: top-level key) or mounted secret files.",
			DocURL:  "https://docs.docker.com/compose/use-secrets/",
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("SEC004").Pass("No secret environment variables without Docker secrets found.")}
	}
	return findings
}
