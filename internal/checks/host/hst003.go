package host

import (
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst003{}) }

type hst003 struct{}

func (c *hst003) ID() string              { return catalog.Get("HST003").ID }
func (c *hst003) Title() string           { return catalog.Get("HST003").Title }
func (c *hst003) Group() model.CheckGroup { return catalog.Get("HST003").Group }

func (c *hst003) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST003")}
	}
	cf, ok := configBySchema(ctx.Collector, "sshd-effective")
	if !ok {
		return []model.Finding{notAssessed("HST003")}
	}

	source := cf.Values["_source"]

	// Condition 1: password authentication enabled (or absent = default yes).
	passVal, passPresent := sshdVal(cf, "passwordauthentication")
	passAuthOn := !passPresent || strings.EqualFold(passVal, "yes")

	// Condition 2: root login permitted.
	rootVal, _ := sshdVal(cf, "permitrootlogin")
	rootLoginOn := strings.EqualFold(rootVal, "yes") || strings.EqualFold(rootVal, "prohibit-password")

	if !passAuthOn || !rootLoginOn {
		return []model.Finding{catalog.Get("HST003").Pass("SSH password-root combination is not configured.")}
	}

	// Condition 3: sshd socket bound non-loopback on port 22.
	// We require socket data to fire the fatal finding.
	if len(ctx.Collector.Sockets) == 0 {
		return []model.Finding{notAssessed("HST003")}
	}
	sock, nonLoopback := socketNonLoopback(ctx.Collector, 22)
	if !nonLoopback {
		// Loopback only — composite condition not met for internet exposure.
		f := catalog.Get("HST003").Pass("SSH is password+root-enabled but bound only to loopback.")
		return []model.Finding{f}
	}

	// All three conditions met. Gate Fatal on _source=effective.
	if source != "effective" {
		// Static parse: fire with ConfidenceMedium, non-Fatal.
		f := catalog.Get("HST003").Finding()
		f.ExposureClass = exposureFromBind(sock.Bind)
		f.Confidence = model.ConfidenceMedium
		f.Fatal = false
		f.Resource = "sshd"
		f.Evidence = "passwordauthentication=yes, permitrootlogin=" + rootVal + ", sshd bound to " + sock.Bind + ":22 (config source: static — confirm with sshd -T)"
		f.Fix = model.Fix{
			Summary: "Disable PasswordAuthentication and PermitRootLogin in sshd_config, then reload sshd.",
			Commands: []string{
				"echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/99-keelix.conf",
				"echo 'PermitRootLogin no' >> /etc/ssh/sshd_config.d/99-keelix.conf",
				"systemctl reload sshd",
			},
		}
		return []model.Finding{f}
	}

	f := catalog.Get("HST003").Finding()
	f.ExposureClass = exposureFromBind(sock.Bind)
	f.Resource = "sshd"
	f.Evidence = "passwordauthentication=yes, permitrootlogin=" + rootVal + ", sshd bound to " + sock.Bind + ":22"
	f.Fix = model.Fix{
		Summary: "Disable PasswordAuthentication and PermitRootLogin in sshd_config, then reload sshd.",
		Commands: []string{
			"echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config.d/99-keelix.conf",
			"echo 'PermitRootLogin no' >> /etc/ssh/sshd_config.d/99-keelix.conf",
			"systemctl reload sshd",
		},
	}
	return []model.Finding{f}
}
