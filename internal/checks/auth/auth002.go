package auth

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&auth002{}) }

type auth002 struct{}

func (c *auth002) ID() string              { return catalog.Get("AUTH002").ID }
func (c *auth002) Title() string           { return catalog.Get("AUTH002").Title }
func (c *auth002) Group() model.CheckGroup { return catalog.Get("AUTH002").Group }

// hasPasswordOverride returns true if the service environment contains a password-like
// variable that is set to a non-weak literal or a ${reference}, suggesting the
// default has been overridden.
func hasPasswordOverride(svc *model.Service) bool {
	for name, val := range svc.Environment {
		upper := strings.ToUpper(name)
		if !strings.Contains(upper, "PASSWORD") &&
			!strings.Contains(upper, "PASS") &&
			!strings.Contains(upper, "PWD") &&
			!strings.Contains(upper, "SECRET") {
			continue
		}
		// A ${reference} counts as a potential override.
		if strings.HasPrefix(val, "${") || strings.HasPrefix(val, "$") {
			return true
		}
		// A non-empty, non-weak literal counts as a strong override.
		if val != "" && !intel.IsWeakPassword(val) {
			return true
		}
	}
	return false
}

func (c *auth002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Stack == nil || len(ctx.Stack.Services) == 0 {
		return []model.Finding{notAssessed("AUTH002")}
	}

	var findings []model.Finding
	foundKnown := false

	for _, svc := range ctx.Stack.Services {
		if svc.Image == "" {
			continue
		}
		creds, ok := intel.DefaultCredentials(svc.Image)
		if !ok {
			continue
		}
		foundKnown = true

		// If there is an obvious override, treat as mitigated.
		if hasPasswordOverride(svc) {
			continue
		}

		// Emit one finding per service; use the first credential entry for the note.
		cred := creds[0]
		f := catalog.Get("AUTH002").Finding()
		f.Service = svc.Name
		f.Resource = fmt.Sprintf("image %s", intel.ImageBase(svc.Image))
		f.Evidence = fmt.Sprintf(
			"image %q ships with documented default credentials (username: %q); no password override detected in service environment",
			intel.ImageBase(svc.Image), cred.Username,
		)
		f.Metadata = map[string]string{
			"default_username": cred.Username,
			"note":             cred.Note,
		}
		f.Fix = model.Fix{
			Summary: fmt.Sprintf("Change the default credentials for %s immediately. Set a strong password via the appropriate environment variable.", intel.ImageBase(svc.Image)),
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		msg := "No well-known images with default credentials found."
		if foundKnown {
			msg = "All well-known images with default credentials appear to have overrides configured."
		}
		return []model.Finding{catalog.Get("AUTH002").Pass(msg)}
	}
	return findings
}
