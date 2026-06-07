package host

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&hst040{}) }

type hst040 struct{}

func (c *hst040) ID() string              { return catalog.Get("HST040").ID }
func (c *hst040) Title() string           { return catalog.Get("HST040").Title }
func (c *hst040) Group() model.CheckGroup { return catalog.Get("HST040").Group }

// sysctlChecks defines the expected minimum-good values for each sysctl key.
// A finding fires if the observed value indicates the control is weakened.
var sysctlChecks = []struct {
	key     string
	weakVal string // fire if value matches this (or is absent for ASLR)
	note    string
}{
	{"kernel.randomize_va_space", "0", "ASLR disabled"},
	{"kernel.kptr_restrict", "0", "kernel pointer exposure not restricted"},
	{"kernel.dmesg_restrict", "0", "dmesg not restricted"},
	{"kernel.yama.ptrace_scope", "0", "ptrace scope unrestricted"},
	{"fs.suid_dumpable", "2", "SUID core dumps allowed (fs.suid_dumpable=2)"},
}

func (c *hst040) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("HST040")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("HST040")}
	}
	cf, ok := configBySchema(ctx.Collector, "sysctl")
	if !ok {
		return []model.Finding{notAssessed("HST040")}
	}

	var issues []string
	for _, chk := range sysctlChecks {
		v, present := cf.Values[chk.key]
		if !present {
			continue
		}
		if v == chk.weakVal {
			issues = append(issues, chk.key+"="+v+" ("+chk.note+")")
		}
	}
	// Special case: randomize_va_space must be 2; 1 is partial ASLR.
	if v, ok := cf.Values["kernel.randomize_va_space"]; ok && v == "1" {
		issues = append(issues, "kernel.randomize_va_space=1 (partial ASLR only; set to 2)")
	}

	if len(issues) == 0 {
		return []model.Finding{catalog.Get("HST040").Pass("Kernel hardening sysctl values are adequate.")}
	}
	f := catalog.Get("HST040").Finding()
	f.Resource = "/proc/sys"
	f.Evidence = joinStrings(issues, "; ")
	f.Fix = model.Fix{
		Summary: "Add the following to /etc/sysctl.d/99-keelix.conf and run sysctl --system.",
		Diff: `kernel.randomize_va_space = 2
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0`,
	}
	return []model.Finding{f}
}
