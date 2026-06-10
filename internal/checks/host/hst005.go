package host

import (
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst005{}) }

type hst005 struct{}

func (c *hst005) ID() string              { return catalog.Get("HST005").ID }
func (c *hst005) Title() string           { return catalog.Get("HST005").Title }
func (c *hst005) Group() model.CheckGroup { return catalog.Get("HST005").Group }

func (c *hst005) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST005")}
	}
	cf, ok := configBySchema(ctx.Collector, "sshd-effective")
	if !ok {
		return []model.Finding{notAssessed("HST005")}
	}

	// Only relevant when password auth is on.
	passVal, passPresent := sshdVal(cf, "passwordauthentication")
	if passPresent && !strings.EqualFold(passVal, "yes") {
		return []model.Finding{catalog.Get("HST005").Pass("Password authentication is off; brute-force protection less critical.")}
	}

	// Detect fail2ban presence via the signals the real collectors emit:
	//   (a) a process whose Comm is "fail2ban-server" or "fail2ban", OR
	//   (b) a FileFact present under /etc/fail2ban (the walker-collected prefix).
	// The dead branch that keyed off SchemaID=="fail2ban" on Configs has been
	// removed: no collector emits a ConfigFact with that SchemaID.
	if hasProcess(ctx.Collector, "fail2ban-server") || hasProcess(ctx.Collector, "fail2ban") {
		return []model.Finding{catalog.Get("HST005").Pass("fail2ban process detected.")}
	}
	for _, ff := range ctx.Collector.Files {
		if ff.Exists && strings.HasPrefix(ff.Path, "/etc/fail2ban/") {
			return []model.Finding{catalog.Get("HST005").Pass("fail2ban configuration file detected under /etc/fail2ban.")}
		}
	}

	f := catalog.Get("HST005").Finding()
	f.ExposureClass = model.ExposureLocalhost
	f.Resource = "sshd"
	f.Evidence = "No fail2ban process or configuration detected; password authentication is enabled"
	f.Fix = model.Fix{
		Summary: "Install and configure fail2ban to protect SSH from brute-force attacks.",
		Commands: []string{
			"apt-get install -y fail2ban",
			"systemctl enable --now fail2ban",
		},
	}
	return []model.Finding{f}
}
