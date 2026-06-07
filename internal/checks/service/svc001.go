package service

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&svc001{}) }

type svc001 struct{}

func (c *svc001) ID() string              { return catalog.Get("SVC001").ID }
func (c *svc001) Title() string           { return catalog.Get("SVC001").Title }
func (c *svc001) Group() model.CheckGroup { return catalog.Get("SVC001").Group }

func (c *svc001) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC001")}
	}
	cf, ok := configBySchema(ctx.Collector, "redis-conf")
	if !ok {
		return []model.Finding{notAssessed("SVC001")}
	}

	requirepassPresent := cf.Values["requirepass.present"]
	protectedMode := strings.ToLower(cf.Values["protected-mode"])
	bind := cf.Values["bind"]

	// Triad: all three conditions must hold to fire.
	noAuth := requirepassPresent == "false"
	protectedOff := protectedMode == "no"
	// R3-5 / R4-1: field-split the bind directive — Redis accepts multiple
	// space-separated addresses (e.g. "127.0.0.1 ::1").
	//
	// R4-1a: Redis 7 uses an optional-address prefix "-" (e.g. "-::1") meaning
	// "bind if available, skip if not". Strip a leading "-" before the loopback
	// comparison so "-::1" and "-127.0.0.1" are treated as loopback.
	//
	// R4-1b: an absent/empty bind directive means Redis listens on all interfaces
	// (0.0.0.0 default), which is public. Treat empty bind as bindPublic=true.
	//
	// A bind is only public if at least ONE (stripped) token is non-loopback.
	tokens := strings.Fields(bind)
	bindPublic := len(tokens) == 0 // absent bind → default 0.0.0.0 → public
	for _, token := range tokens {
		stripped := strings.TrimPrefix(token, "-")
		if stripped != "127.0.0.1" && stripped != "::1" && stripped != "localhost" {
			bindPublic = true
			break
		}
	}

	if noAuth && protectedOff && bindPublic {
		f := catalog.Get("SVC001").Finding()
		f.Resource = "redis"
		f.Evidence = "requirepass absent, protected-mode no, bind " + bind
		f.Metadata = map[string]string{"port": "6379"}
		f.Fix = model.Fix{
			Summary: "Set a requirepass in redis.conf, or set protected-mode yes, or bind to 127.0.0.1.",
			Diff:    "requirepass <strong-password>\nprotected-mode yes",
		}
		return []model.Finding{f}
	}
	return []model.Finding{catalog.Get("SVC001").Pass("Redis authentication triad is satisfied.")}
}
