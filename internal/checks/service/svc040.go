package service

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&svc040{}) }

type svc040 struct{}

func (c *svc040) ID() string              { return catalog.Get("SVC040").ID }
func (c *svc040) Title() string           { return catalog.Get("SVC040").Title }
func (c *svc040) Group() model.CheckGroup { return catalog.Get("SVC040").Group }

func (c *svc040) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC040")}
	}
	cf, ok := configBySchema(ctx.Collector, "smb-conf")
	if !ok {
		return []model.Finding{notAssessed("SVC040")}
	}
	if cf.Values["guest-ok-shares"] == "" {
		return []model.Finding{catalog.Get("SVC040").Pass("No Samba shares allow guest access.")}
	}
	f := catalog.Get("SVC040").Finding()
	f.Resource = "smb.conf"
	f.Evidence = "guest-ok shares: " + cf.Values["guest-ok-shares"] + " (one or more shares have 'guest ok = yes')"
	f.Metadata = map[string]string{"port": "445"}
	f.Fix = model.Fix{
		Summary: "Remove 'guest ok = yes' from all share definitions in smb.conf and set 'map to guest = never' in [global].",
		Diff:    "   guest ok = yes  ->  (remove line)",
	}
	return []model.Finding{f}
}
