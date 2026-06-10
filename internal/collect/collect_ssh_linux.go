//go:build linux

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jakelamon/keelix/internal/model"
)

// collectSSH collects the effective sshd configuration as a ConfigFact.
//
// When opts.Privileged is true and the process runs as root, it executes
// `sshd -T` which returns the fully resolved effective configuration
// (compiled defaults + Include + .d/ overrides). The resulting ConfigFact
// has _source unset (authoritative effective source).
//
// Otherwise it static-parses /etc/ssh/sshd_config (and any readable
// /etc/ssh/sshd_config.d/*.conf files) and sets Values["_source"]="static"
// so checks can apply ConfidenceMedium and must not fire the Fatal HST003.
func collectSSH(opts Options) (model.ConfigFact, error) {
	fact := model.ConfigFact{Source: "sshd-effective"}

	if opts.Privileged && os.Geteuid() == 0 {
		return collectSSHEffective(fact)
	}
	return collectSSHStatic(fact)
}

// collectSSHEffective runs `sshd -T` and parses the output.
func collectSSHEffective(fact model.ConfigFact) (model.ConfigFact, error) {
	out, err := exec.Command("sshd", "-T").Output()
	if err != nil {
		// Fall through to static parse on exec failure.
		return collectSSHStatic(fact)
	}
	vals, schemaID, known := parseSSHDashT(out)
	fact.SchemaID = schemaID
	fact.SchemaKnown = known
	if known {
		fact.Values = vals
	}
	return fact, nil
}

// collectSSHStatic reads /etc/ssh/sshd_config (and .d/*.conf) and merges them.
// The last directive wins (matching sshd precedence for the main file; .d/ files
// are merged in glob order, main file takes precedence by being parsed first and
// .d/ overrides applied on top — matching openssh Include semantics).
func collectSSHStatic(fact model.ConfigFact) (model.ConfigFact, error) {
	merged := make(map[string]string)

	// Parse main config first.
	if b, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil { // #nosec G304 -- fixed path
		if vals, _, known := parseSSHDConfig(b); known {
			for k, v := range vals {
				merged[k] = v
			}
		}
	}

	// Parse .d/*.conf files in glob order, last-write wins within this layer.
	if matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		for _, p := range matches {
			if b, err := os.ReadFile(p); err == nil { // #nosec G304 -- glob under fixed dir
				if vals, _, known := parseSSHDConfig(b); known {
					for k, v := range vals {
						if k == "_source" {
							continue
						}
						merged[k] = v
					}
				}
			}
		}
	}

	// Remove _source written by parseSSHDConfig for intermediate merges;
	// we set it explicitly once at the end.
	delete(merged, "_source")

	if len(merged) == 0 {
		fact.SchemaID = "sshd-effective"
		fact.SchemaKnown = false
		return fact, nil
	}

	merged["_source"] = "static"
	fact.SchemaID = "sshd-effective"
	fact.SchemaKnown = true
	fact.Values = merged

	// sshd config values are boolean/numeric state, not credentials — do NOT
	// call redactConfigValues here. classOf() matches on key substrings such as
	// "password" and "key", which would corrupt "passwordauthentication",
	// "permitemptypasswords", and "pubkeyauthentication" (all expected to hold
	// "yes"/"no") causing every SSH-config check to silently read "[secret]".

	return fact, nil
}

// sshdPortFromConfig extracts the "port" value from the sshd-effective
// ConfigFact. Returns "22" when absent (the OpenSSH compiled default).
func sshdPortFromConfig(vals map[string]string) string {
	if p, ok := vals["port"]; ok && p != "" {
		return p
	}
	return "22"
}

// sshdListeningNonLoopback returns true when at least one listening socket
// matches the sshd port AND is bound to a non-loopback address.
// It returns false immediately when sigs is nil (no socket data collected).
func sshdListeningNonLoopback(sigs *model.Signals, vals map[string]string) bool {
	if sigs == nil {
		return false
	}
	portStr := sshdPortFromConfig(vals)
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return false
		}
		port = port*10 + int(c-'0')
	}
	if port == 0 {
		port = 22
	}
	for _, sock := range sigs.Sockets {
		if sock.Port != port {
			continue
		}
		b := sock.Bind
		if strings.HasPrefix(b, "127.") || b == "::1" || b == "" {
			continue
		}
		return true
	}
	return false
}
