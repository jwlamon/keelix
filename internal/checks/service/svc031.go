package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc031{}) }

type svc031 struct{}

func (c *svc031) ID() string              { return catalog.Get("SVC031").ID }
func (c *svc031) Title() string           { return catalog.Get("SVC031").Title }
func (c *svc031) Group() model.CheckGroup { return catalog.Get("SVC031").Group }

func (c *svc031) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC031")}
	}
	cf, ok := configBySchema(ctx.Collector, "gitea-ini")
	if !ok {
		return []model.Finding{notAssessed("SVC031")}
	}
	// INSTALL_LOCK is only emitted by the parser when explicitly present.
	// When absent the operator may have installed via environment variable or
	// the key was omitted post-install — we cannot determine the lock state.
	installLockVal, installLockPresent := cf.Values["INSTALL_LOCK"]
	if !installLockPresent {
		// Cannot assess: INSTALL_LOCK absent from config file.
		na := notAssessed("SVC031")
		na.Evidence = "INSTALL_LOCK key absent from app.ini; cannot determine installation lock state (may be set via environment)"
		return []model.Finding{na}
	}
	installUnlocked := installLockVal == "false"
	openRegistration := cf.Values["registration.open"] == "true"
	if !installUnlocked && !openRegistration {
		return []model.Finding{catalog.Get("SVC031").Pass("Gitea installation is locked and open registration is disabled.")}
	}
	f := catalog.Get("SVC031").Finding()
	f.Resource = "gitea"
	f.Metadata = map[string]string{"port": "3000"}
	switch {
	case installUnlocked && openRegistration:
		f.Evidence = "INSTALL_LOCK=false; registration.open=true"
	case installUnlocked:
		f.Evidence = "INSTALL_LOCK=false (setup wizard accessible)"
	default:
		f.Evidence = "registration.open=true (open self-registration)"
	}
	f.Fix = model.Fix{
		Summary: "Set INSTALL_LOCK=true in app.ini [security] and set DISABLE_REGISTRATION=true in [service] to prevent unauthorized account creation.",
		Diff:    "[security]\nINSTALL_LOCK = true\n\n[service]\nDISABLE_REGISTRATION = true",
	}
	return []model.Finding{f}
}
