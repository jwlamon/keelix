package collect

import (
	"strings"
)

// sshdKeys is the ordered set of sshd directive keys SP2 cares about.
// All keys are lower-cased; parseSSHDashT and parseSSHDConfig normalize to these.
var sshdKeys = []string{
	"permitrootlogin",
	"passwordauthentication",
	"pubkeyauthentication",
	"permitemptypasswords",
	"maxauthtries",
	"logingracetime",
	"x11forwarding",
	"allowusers",
	"allowgroups",
	"port",
	"kbdinteractiveauthentication",
}

var sshdKeySet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(sshdKeys))
	for _, k := range sshdKeys {
		m[k] = struct{}{}
	}
	return m
}()

// parseSSHDashT parses the output of `sshd -T` (the effective configuration
// including compiled defaults, Include directives, and .d/ overrides).
// Each line is "key value..."; we lower-case the key and capture only the
// keys in sshdKeys. Sets Values["_source"]="effective" so the Fatal gate in
// HST003 engages on the authoritative effective path. Returns schemaID
// "sshd-effective".
func parseSSHDashT(b []byte) (map[string]string, string, bool) {
	vals := make(map[string]string)
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sp := strings.IndexByte(line, ' ')
		if sp <= 0 {
			continue
		}
		key := strings.ToLower(line[:sp])
		val := strings.TrimSpace(line[sp+1:])
		if _, ok := sshdKeySet[key]; ok {
			vals[key] = val
		}
	}
	if len(vals) == 0 {
		return nil, "", false
	}
	vals["_source"] = "effective"
	return vals, "sshd-effective", true
}

// parseSSHDConfig parses a static /etc/ssh/sshd_config (or sshd_config.d/*.conf)
// file. Directives are "Key Value" lines (case-insensitive key). The result
// always sets Values["_source"]="static" to signal that checks must apply
// ConfidenceMedium and must not fire the Fatal HST003 off inferred defaults.
// Returns schemaID "sshd-effective".
func parseSSHDConfig(b []byte) (map[string]string, string, bool) {
	vals := make(map[string]string)
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// sshd_config uses whitespace (space or tab) as separator.
		var key, val string
		if sp := strings.IndexAny(line, " \t"); sp > 0 {
			key = strings.ToLower(line[:sp])
			val = strings.TrimSpace(line[sp+1:])
		} else {
			key = strings.ToLower(line)
			val = ""
		}
		if _, ok := sshdKeySet[key]; ok {
			vals[key] = val
		}
	}
	if len(vals) == 0 {
		return nil, "", false
	}
	vals["_source"] = "static"
	return vals, "sshd-effective", true
}
