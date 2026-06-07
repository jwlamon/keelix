package host

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst020{}) }

type hst020 struct{}

func (c *hst020) ID() string              { return catalog.Get("HST020").ID }
func (c *hst020) Title() string           { return catalog.Get("HST020").Title }
func (c *hst020) Group() model.CheckGroup { return catalog.Get("HST020").Group }

func (c *hst020) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST020")}
	}

	// Iterate ALL accounts-sudoers facts: /etc/sudoers is Configs[0] and the
	// merged /etc/sudoers.d result is Configs[1].  Using configBySchema (first
	// match only) causes a silent miss when /etc/sudoers is clean but a drop-in
	// fragment carries NOPASSWD.  We OR the nopasswd.present flag across all
	// matching facts and fire on the first positive hit.
	found := false
	for _, cf := range ctx.Collector.Configs {
		if cf.SchemaID != "accounts-sudoers" || !cf.SchemaKnown {
			continue
		}
		found = true
		if cf.Values["nopasswd.present"] == "true" {
			f := catalog.Get("HST020").Finding()
			f.ExposureClass = model.ExposureLocalhost
			f.Resource = "/etc/sudoers"
			f.Evidence = "NOPASSWD directive found in sudoers configuration"
			if rules := cf.Values["nopasswd.rules"]; rules != "" {
				f.Evidence += ": " + rules
			}
			f.Fix = model.Fix{
				Summary: "Remove NOPASSWD from sudoers rules; require password for all sudo access.",
			}
			return []model.Finding{f}
		}
	}
	if !found {
		return []model.Finding{notAssessed("HST020")}
	}
	return []model.Finding{catalog.Get("HST020").Pass("No NOPASSWD rules found in sudoers.")}
}
