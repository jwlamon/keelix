package host

import (
	"strconv"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst023{}) }

type hst023 struct{}

func (c *hst023) ID() string              { return catalog.Get("HST023").ID }
func (c *hst023) Title() string           { return catalog.Get("HST023").Title }
func (c *hst023) Group() model.CheckGroup { return catalog.Get("HST023").Group }

func (c *hst023) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST023")}
	}
	ff, ok := fileByPath(ctx.Collector, "/etc/shadow")
	if !ok || !ff.Exists {
		return []model.Finding{notAssessed("HST023")}
	}
	// Mode is an octal string, e.g. "0600". Parse and check group+world bits (0o077):
	// any group or other read/write/execute bit means the password hashes are
	// potentially accessible to non-root users, which is a security risk.
	mode, err := strconv.ParseUint(ff.Mode, 8, 32)
	if err != nil {
		return []model.Finding{notAssessed("HST023")}
	}
	if mode&0o077 != 0 {
		f := catalog.Get("HST023").Finding()
		f.Resource = "/etc/shadow"
		f.Evidence = "/etc/shadow has mode " + ff.Mode + " (group or world readable/writable)"
		f.Fix = model.Fix{
			Summary:  "Restrict /etc/shadow to root-only access.",
			Commands: []string{"chmod 600 /etc/shadow", "chown root:root /etc/shadow"},
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("HST023").Pass("/etc/shadow permissions are restrictive.")}
}
