package service

import (
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&svc010{}) }

type svc010 struct{}

func (c *svc010) ID() string              { return catalog.Get("SVC010").ID }
func (c *svc010) Title() string           { return catalog.Get("SVC010").Title }
func (c *svc010) Group() model.CheckGroup { return catalog.Get("SVC010").Group }

// arrImageDefaultPorts is an ordered slice mapping *arr image-name keywords to
// their documented default web-UI port. Entries are sorted longest-keyword-
// first so that a more specific keyword (e.g. "prowlarr") always wins over a
// shorter one that is a suffix of it. The slice is iterated in order, so the
// first match wins — guaranteeing deterministic results (R4-4).
var arrImageDefaultPorts = []struct{ keyword, port string }{
	{"prowlarr", "9696"},
	{"readarr", "8787"},
	{"sonarr", "8989"},
	{"lidarr", "8686"},
	{"radarr", "7878"},
}

// arrPortFromStack inspects ctx.Stack for services whose image matches an *arr
// keyword, returning the per-image default port for the first match.
// Returns "" when no *arr service is found (caller falls back to "7878").
func arrPortFromStack(stack *model.Stack) string {
	if stack == nil {
		return ""
	}
	for _, svc := range stack.Services {
		base := intel.ImageBase(svc.Image)
		for _, entry := range arrImageDefaultPorts {
			if strings.Contains(base, entry.keyword) {
				return entry.port
			}
		}
	}
	return ""
}

func (c *svc010) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("SVC010")}
	}
	cf, ok := configBySchema(ctx.Collector, "arr-config")
	if !ok {
		return []model.Finding{notAssessed("SVC010")}
	}
	if cf.Values["AuthenticationMethod"] != "None" {
		return []model.Finding{catalog.Get("SVC010").Pass("*arr authentication is enabled.")}
	}
	// R2-7: use the port extracted from config.xml <Port> by parseArrConfig.
	// R3-4: when <Port> is absent, resolve the per-image default from the stack
	// image (sonarr=8989, prowlarr=9696, lidarr=8686, readarr=8787, radarr=7878)
	// before falling back to the generic 7878 default.
	port := cf.Values["Port"]
	if port == "" {
		port = arrPortFromStack(ctx.Stack)
	}
	if port == "" {
		port = "7878"
	}
	f := catalog.Get("SVC010").Finding()
	f.Resource = "arr-config"
	f.Evidence = "AuthenticationMethod=None"
	f.Metadata = map[string]string{"port": port}
	f.Fix = model.Fix{
		Summary: "Set AuthenticationMethod to Forms or Basic in the *arr config.xml, then restart the service.",
		Diff:    "<AuthenticationMethod>None</AuthenticationMethod>  ->  <AuthenticationMethod>Forms</AuthenticationMethod>",
	}
	return []model.Finding{f}
}
