package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc002{}) }

type svc002 struct{}

func (c *svc002) ID() string              { return catalog.Get("SVC002").ID }
func (c *svc002) Title() string           { return catalog.Get("SVC002").Title }
func (c *svc002) Group() model.CheckGroup { return catalog.Get("SVC002").Group }

func (c *svc002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC002")}
	}
	cf, ok := configBySchema(ctx.Collector, "mongod-conf")
	if !ok {
		return []model.Finding{notAssessed("SVC002")}
	}

	// The parser emits "" when security.authorization is absent or not "enabled".
	// It emits "enabled" when set — but redactConfigValues masks that to "[secret]"
	// (the key ends in "authorization" which the redactor treats as a credential path).
	// Firing condition: value is "" (not configured) — any non-empty value means
	// either "enabled" (safe) or a redacted credential (treated conservatively as set).
	if cf.Values["security.authorization"] == "" {
		f := catalog.Get("SVC002").Finding()
		f.Resource = "mongodb"
		f.Evidence = "security.authorization not set in mongod.conf"
		f.Metadata = map[string]string{"port": "27017"}
		f.Fix = model.Fix{
			Summary: "Set security.authorization: enabled in mongod.conf and restart mongod.",
			Diff:    "security:\n  authorization: enabled",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC002").Pass("MongoDB authorization is enabled.")}
}
