package collect

import (
	"fmt"
	"strings"
)

// parsePasswd parses /etc/passwd and returns security-relevant derived facts.
// It NEVER stores the full passwd file; only derived counts and account names
// for uid-0 accounts are emitted.
//
// Values emitted:
//
//	uid0.accounts   — comma-separated list of account names whose UID==0
//	duplicate.uids  — "true" when more than one account has UID==0
func parsePasswd(b []byte) (map[string]string, string, bool) {
	var uid0Names []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		// /etc/passwd: name:password:uid:gid:comment:home:shell (7 fields minimum)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		uid := fields[2]
		if uid == "0" {
			uid0Names = append(uid0Names, name)
		}
	}
	if len(uid0Names) == 0 {
		// No UID-0 accounts at all is unusual but not a parse failure.
		return map[string]string{
			"uid0.accounts":  "",
			"duplicate.uids": "false",
		}, "accounts-passwd", true
	}
	dup := "false"
	if len(uid0Names) > 1 {
		dup = "true"
	}
	return map[string]string{
		"uid0.accounts":  strings.Join(uid0Names, ","),
		"duplicate.uids": dup,
	}, "accounts-passwd", true
}

// parseShadow parses /etc/shadow and emits only security-relevant derived facts.
// Hash fields are DROPPED at parse time — they are never stored or emitted.
// An empty password field (the second colon-delimited field) means the account
// has no password (distinct from "!" or "*" which mean locked/disabled).
//
// Values emitted:
//
//	empty.password.accounts — comma-separated names with empty password field
func parseShadow(b []byte) (map[string]string, string, bool) {
	var emptyPwAccounts []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// /etc/shadow: name:password:lastchg:min:max:warn:inactive:expire:reserved
		// Password field empty string means no password.
		colon1 := strings.IndexByte(line, ':')
		if colon1 <= 0 {
			continue
		}
		name := line[:colon1]
		rest := line[colon1+1:]
		colon2 := strings.IndexByte(rest, ':')
		if colon2 < 0 {
			continue
		}
		pwField := rest[:colon2]
		// Empty string = no password; "!" or "!!" = locked; "*" = no login.
		// Only empty string is the security-relevant "empty password" condition.
		if pwField == "" {
			emptyPwAccounts = append(emptyPwAccounts, name)
		}
		// Hash value (pwField) is intentionally discarded — never stored.
	}
	vals := map[string]string{
		"empty.password.accounts": strings.Join(emptyPwAccounts, ","),
	}
	return vals, "accounts-shadow", true
}

// parseLoginDefs parses /etc/login.defs, emitting PASS_MAX_DAYS, UMASK,
// and ENCRYPT_METHOD. Lines are KEY<whitespace>VALUE; comments start with '#'.
func parseLoginDefs(b []byte) (map[string]string, string, bool) {
	want := map[string]bool{
		"PASS_MAX_DAYS":  true,
		"UMASK":          true,
		"ENCRYPT_METHOD": true,
	}
	vals := make(map[string]string)
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sp := strings.IndexAny(line, " \t")
		if sp <= 0 {
			continue
		}
		key := line[:sp]
		val := strings.TrimSpace(line[sp+1:])
		if want[key] {
			vals[key] = val
		}
	}
	if len(vals) == 0 {
		return nil, "", false
	}
	return vals, "accounts-logindefs", true
}

// parseSudoers parses a single sudoers file (either /etc/sudoers or one
// /etc/sudoers.d/* fragment). Callers that want full coverage must call this
// for each fragment and merge the results; see collectSudoersFacts.
// It detects NOPASSWD rules and emits:
//
//	nopasswd.present — "true" when any NOPASSWD rule is found
//	nopasswd.rules   — a redacted rule summary (no raw commands or paths)
//
// The raw command specifications are replaced with a count token to avoid
// emitting potentially-sensitive paths (e.g. internal scripts).
func parseSudoers(b []byte) (map[string]string, string, bool) {
	var nopasswdRules []string
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		upper := strings.ToUpper(line)
		if strings.Contains(upper, "NOPASSWD") {
			// Redact: emit "user ALL=(ALL) NOPASSWD: [redacted]" shape.
			sp := strings.IndexAny(line, " \t")
			user := line
			if sp > 0 {
				user = line[:sp]
			}
			nopasswdRules = append(nopasswdRules, fmt.Sprintf("%s ... NOPASSWD:[redacted]", user))
		}
	}
	present := "false"
	if len(nopasswdRules) > 0 {
		present = "true"
	}
	vals := map[string]string{
		"nopasswd.present": present,
		"nopasswd.rules":   strings.Join(nopasswdRules, "; "),
	}
	return vals, "accounts-sudoers", true
}
