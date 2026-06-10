//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/jakelamon/keelix/internal/model"
)

// sysctlKeys maps the dot-notation sysctl key (used in ConfigFact.Values) to
// its relative path under /proc/sys (dots replaced by slashes except for
// yama which has a subdir).
var sysctlKeys = []struct {
	Key  string // dot-notation key emitted in Values
	Path string // relative path under /proc/sys (or the base dir in tests)
}{
	{"kernel.randomize_va_space", "kernel/randomize_va_space"},
	{"kernel.kptr_restrict", "kernel/kptr_restrict"},
	{"kernel.dmesg_restrict", "kernel/dmesg_restrict"},
	{"kernel.yama.ptrace_scope", "kernel/yama/ptrace_scope"},
	{"fs.suid_dumpable", "fs/suid_dumpable"},
}

// collectSysctl reads the fixed sysctl keys from /proc/sys and returns a
// ConfigFact{SchemaID:"sysctl"}. All paths are world-readable; no exec is
// used. Missing paths produce no entry (best-effort: a kernel without Yama
// simply has no ptrace_scope key).
func collectSysctl() (model.ConfigFact, error) {
	return collectSysctlFromDir("/proc/sys"), nil
}

// collectSysctlFromDir is the testable core: it reads from base instead of
// the real /proc/sys so tests can inject a synthetic tree.
func collectSysctlFromDir(base string) model.ConfigFact {
	fact := model.ConfigFact{
		Source:   "sysctl",
		SchemaID: "sysctl",
	}
	vals := make(map[string]string)
	for _, entry := range sysctlKeys {
		p := filepath.Join(base, entry.Path)
		b, err := os.ReadFile(p) // #nosec G304 -- path constructed from fixed sysctlKeys table
		if err != nil {
			continue
		}
		vals[entry.Key] = strings.TrimSpace(string(b))
	}
	if len(vals) == 0 {
		return fact
	}
	fact.SchemaKnown = true
	fact.Values = vals
	return fact
}
