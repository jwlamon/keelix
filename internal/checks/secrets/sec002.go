package secrets

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&sec002{}) }

type sec002 struct{}

func (c *sec002) ID() string              { return catalog.Get("SEC002").ID }
func (c *sec002) Title() string           { return catalog.Get("SEC002").Title }
func (c *sec002) Group() model.CheckGroup { return catalog.Get("SEC002").Group }

func (c *sec002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil {
		return nil
	}
	// No .env file at all — not applicable.
	if ctx.Stack.EnvPath == "" {
		return nil
	}

	if ctx.Stack.EnvCommitted {
		f := catalog.Get("SEC002").Finding()
		f.Evidence = fmt.Sprintf("%s is tracked in git", ctx.Stack.EnvPath)
		f.Fix = model.Fix{
			Summary: "Remove the .env file from version control, rotate any leaked secrets, and add it to .gitignore.",
			Commands: []string{
				"git rm --cached " + ctx.Stack.EnvPath,
				`echo ".env" >> .gitignore`,
			},
			DocURL: "https://docs.docker.com/compose/environment-variables/",
		}
		return []model.Finding{f}
	}

	return []model.Finding{catalog.Get("SEC002").Pass(fmt.Sprintf("%s exists but is not tracked in git.", ctx.Stack.EnvPath))}
}
