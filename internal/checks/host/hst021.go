package host

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst021{}) }

type hst021 struct{}

func (c *hst021) ID() string              { return catalog.Get("HST021").ID }
func (c *hst021) Title() string           { return catalog.Get("HST021").Title }
func (c *hst021) Group() model.CheckGroup { return catalog.Get("HST021").Group }

func (c *hst021) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST021")}
	}
	cf, ok := configBySchema(ctx.Collector, "accounts-passwd")
	if !ok {
		return []model.Finding{notAssessed("HST021")}
	}
	uid0accounts := cf.Values["uid0.accounts"]
	if uid0accounts == "" {
		return []model.Finding{catalog.Get("HST021").Pass("Only one UID 0 account (root).")}
	}
	// uid0.accounts is a comma-separated list of name:uid pairs.
	parts := strings.Split(uid0accounts, ",")
	if len(parts) <= 1 {
		return []model.Finding{catalog.Get("HST021").Pass("Only one UID 0 account (root).")}
	}
	f := catalog.Get("HST021").Finding()
	f.Resource = "/etc/passwd"
	f.Evidence = "Multiple UID 0 accounts: " + uid0accounts
	f.Fix = model.Fix{
		Summary: "Remove or reassign all accounts with UID 0 except root.",
	}
	return []model.Finding{f}
}
