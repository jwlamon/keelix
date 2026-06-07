package host

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst002{}) }

type hst002 struct{}

func (c *hst002) ID() string              { return catalog.Get("HST002").ID }
func (c *hst002) Title() string           { return catalog.Get("HST002").Title }
func (c *hst002) Group() model.CheckGroup { return catalog.Get("HST002").Group }

func (c *hst002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST002")}
	}
	cf, ok := configBySchema(ctx.Collector, "sshd-effective")
	if !ok {
		return []model.Finding{notAssessed("HST002")}
	}
	val, _ := sshdVal(cf, "permitrootlogin")
	// Fire on "yes" or "prohibit-password"; pass on "no" or "forced-commands-only".
	if strings.EqualFold(val, "yes") || strings.EqualFold(val, "prohibit-password") {
		f := catalog.Get("HST002").Finding()
		f.ExposureClass = model.ExposureLocalhost
		f.Resource = "sshd"
		f.Evidence = "permitrootlogin=" + val
		f.Fix = model.Fix{
			Summary: "Set PermitRootLogin no in /etc/ssh/sshd_config and reload sshd.",
			Commands: []string{
				"echo 'PermitRootLogin no' >> /etc/ssh/sshd_config.d/99-keelix.conf",
				"systemctl reload sshd",
			},
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("HST002").Pass("PermitRootLogin is restricted.")}
}
