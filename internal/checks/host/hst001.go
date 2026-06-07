package host

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst001{}) }

type hst001 struct{}

func (c *hst001) ID() string              { return catalog.Get("HST001").ID }
func (c *hst001) Title() string           { return catalog.Get("HST001").Title }
func (c *hst001) Group() model.CheckGroup { return catalog.Get("HST001").Group }

func (c *hst001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST001")}
	}
	cf, ok := configBySchema(ctx.Collector, "sshd-effective")
	if !ok {
		return []model.Finding{notAssessed("HST001")}
	}
	val, present := sshdVal(cf, "passwordauthentication")
	// SSH default when key is absent is "yes".
	if !present || strings.EqualFold(val, "yes") {
		f := catalog.Get("HST001").Finding()
		f.ExposureClass = model.ExposureLocalhost
		f.Resource = "sshd"
		if !present {
			f.Evidence = "passwordauthentication not set in sshd config (default is yes)"
		} else {
			f.Evidence = "passwordauthentication=yes"
		}
		f.Fix = model.Fix{
			Summary: "Set PasswordAuthentication no in /etc/ssh/sshd_config and reload sshd.",
			Commands: []string{
				"echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/99-keelix.conf",
				"systemctl reload sshd",
			},
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("HST001").Pass("PasswordAuthentication is disabled.")}
}
