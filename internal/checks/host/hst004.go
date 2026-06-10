package host

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&hst004{}) }

type hst004 struct{}

func (c *hst004) ID() string              { return catalog.Get("HST004").ID }
func (c *hst004) Title() string           { return catalog.Get("HST004").Title }
func (c *hst004) Group() model.CheckGroup { return catalog.Get("HST004").Group }

func (c *hst004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST004")}
	}
	cf, ok := configBySchema(ctx.Collector, "sshd-effective")
	if !ok {
		return []model.Finding{notAssessed("HST004")}
	}

	var issues []string

	if v, ok := sshdVal(cf, "maxauthtries"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 4 {
			issues = append(issues, fmt.Sprintf("MaxAuthTries=%d (>4)", n))
		}
	}
	if v, ok := sshdVal(cf, "logingracetime"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 60 {
			issues = append(issues, fmt.Sprintf("LoginGraceTime=%d (>60s)", n))
		}
	}
	if v, _ := sshdVal(cf, "x11forwarding"); strings.EqualFold(v, "yes") {
		issues = append(issues, "X11Forwarding=yes")
	}
	if v, _ := sshdVal(cf, "permitemptypasswords"); strings.EqualFold(v, "yes") {
		issues = append(issues, "PermitEmptyPasswords=yes")
	}

	if len(issues) == 0 {
		return []model.Finding{catalog.Get("HST004").Pass("SSH weak-parameter checks passed.")}
	}
	f := catalog.Get("HST004").Finding()
	f.ExposureClass = model.ExposureLocalhost
	f.Resource = "sshd"
	f.Evidence = joinStrings(issues, "; ")
	f.Fix = model.Fix{
		Summary: "Tighten sshd_config: MaxAuthTries 4, LoginGraceTime 60, X11Forwarding no, PermitEmptyPasswords no.",
	}
	return []model.Finding{f}
}

func joinStrings(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
