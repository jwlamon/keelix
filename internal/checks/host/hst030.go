package host

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst030{}) }

type hst030 struct{}

func (c *hst030) ID() string              { return catalog.Get("HST030").ID }
func (c *hst030) Title() string           { return catalog.Get("HST030").Title }
func (c *hst030) Group() model.CheckGroup { return catalog.Get("HST030").Group }

func (c *hst030) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST030")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("HST030")}
	}
	fw := ctx.Collector.Firewall
	if fw.Backend == "" || fw.Backend == "none" {
		f := catalog.Get("HST030").Finding()
		f.Resource = "firewall"
		f.Evidence = "No host firewall backend detected"
		f.Fix = model.Fix{
			Summary:  "Install and configure a host firewall (ufw, nftables, or firewalld).",
			Commands: []string{"apt-get install -y ufw", "ufw default deny incoming", "ufw enable"},
		}
		return []model.Finding{f}
	}
	di := fw.DefaultInbound
	if di != "deny" && di != "drop" {
		f := catalog.Get("HST030").Finding()
		f.Resource = fw.Backend
		f.Evidence = "DefaultInbound=" + di + "; expected deny or drop"
		f.Fix = model.Fix{
			Summary:  "Set the firewall's default inbound policy to deny or drop.",
			Commands: []string{"ufw default deny incoming"},
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("HST030").Pass("Host firewall is active with default-deny inbound policy.")}
}
