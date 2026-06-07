package service

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&svc030{}) }

type svc030 struct{}

func (c *svc030) ID() string              { return catalog.Get("SVC030").ID }
func (c *svc030) Title() string           { return catalog.Get("SVC030").Title }
func (c *svc030) Group() model.CheckGroup { return catalog.Get("SVC030").Group }

// Run fires when:
//   - admin_token.present == "false"  (no admin token → panel open to all), OR
//   - admin_token.present == "true" AND admin_token.is_argon2 != "true"
//     AND admin_token.length_band == "weak"  (token present but weak plain-text)
//
// Vaultwarden can be configured via a dotenv file (vaultwarden-env schemaID)
// or via the admin-panel config.json (vaultwarden-json schemaID). SVC030 reads
// whichever is present; if neither is collected it returns NotAssessed.
func (c *svc030) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC030")}
	}
	cf, ok := configBySchema(ctx.Collector, "vaultwarden-env")
	if !ok {
		cf, ok = configBySchema(ctx.Collector, "vaultwarden-json")
	}
	if !ok {
		return []model.Finding{notAssessed("SVC030")}
	}
	present := cf.Values["admin_token.present"]
	isArgon2 := cf.Values["admin_token.is_argon2"]
	lengthBand := cf.Values["admin_token.length_band"]

	if present == "false" {
		f := catalog.Get("SVC030").Finding()
		f.Resource = "vaultwarden ADMIN_TOKEN"
		f.Evidence = "admin_token.present=false — admin panel is open to all"
		f.Metadata = map[string]string{"port": "80"}
		f.Fix = model.Fix{
			Summary: "Set ADMIN_TOKEN to an Argon2 hash in vaultwarden.env: generate with `echo -n 'yourpassword' | argon2 'yoursalt' -e` or use the Vaultwarden admin token generator.",
			DocURL:  "https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page",
		}
		return []model.Finding{f}
	}
	if present == "true" && isArgon2 != "true" && lengthBand == "weak" {
		f := catalog.Get("SVC030").Finding()
		f.Resource = "vaultwarden ADMIN_TOKEN"
		f.Evidence = "admin_token.present=true; admin_token.is_argon2=false; admin_token.length_band=weak"
		f.Metadata = map[string]string{"port": "80"}
		f.Fix = model.Fix{
			Summary: "Replace the plain-text ADMIN_TOKEN with an Argon2 hash of a strong (≥20 char) passphrase.",
			DocURL:  "https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page#secure-the-admin_token",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC030").Pass("Vaultwarden admin token is present and uses Argon2 hashing.")}
}
