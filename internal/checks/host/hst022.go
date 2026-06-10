package host

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst022{}) }

type hst022 struct{}

func (c *hst022) ID() string              { return catalog.Get("HST022").ID }
func (c *hst022) Title() string           { return catalog.Get("HST022").Title }
func (c *hst022) Group() model.CheckGroup { return catalog.Get("HST022").Group }

func (c *hst022) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST022")}
	}
	cf, ok := configBySchema(ctx.Collector, "accounts-shadow")
	if !ok {
		// Shadow unreadable or not collected — NotAssessed, not a pass.
		return []model.Finding{notAssessed("HST022")}
	}
	accounts := cf.Values["empty.password.accounts"]
	if accounts == "" {
		return []model.Finding{catalog.Get("HST022").Pass("No accounts with empty passwords found.")}
	}
	f := catalog.Get("HST022").Finding()
	f.Resource = "/etc/shadow"
	f.Evidence = "Accounts with empty passwords: " + accounts
	f.Fix = model.Fix{
		Summary:  "Set passwords for all accounts or lock them with 'passwd -l <user>'.",
		Commands: []string{"passwd -l <username>"},
	}
	return []model.Finding{f}
}
