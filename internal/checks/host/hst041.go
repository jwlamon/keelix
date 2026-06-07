package host

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst041{}) }

type hst041 struct{}

func (c *hst041) ID() string              { return catalog.Get("HST041").ID }
func (c *hst041) Title() string           { return catalog.Get("HST041").Title }
func (c *hst041) Group() model.CheckGroup { return catalog.Get("HST041").Group }

// knownDMCryptProcNames are processes that indicate an active encrypted volume.
var knownDMCryptProcNames = []string{"dmcrypt", "cryptsetup", "luksOpen"}

func (c *hst041) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST041")}
	}
	// Best-effort: look for dmcrypt/cryptsetup processes as a proxy.
	for _, name := range knownDMCryptProcNames {
		if hasProcess(ctx.Collector, name) {
			return []model.Finding{catalog.Get("HST041").Pass("Disk encryption process detected (dm-crypt/LUKS).")}
		}
	}
	f := catalog.Get("HST041").Finding()
	f.Confidence = model.ConfidenceLow
	f.Resource = "host"
	f.Evidence = "No dm-crypt/cryptsetup process detected; disk encryption status unknown"
	f.Fix = model.Fix{
		Summary: "Consider enabling full-disk encryption (LUKS/dm-crypt) for data at rest protection.",
	}
	return []model.Finding{f}
}
