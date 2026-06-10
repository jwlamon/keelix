package collect

import (
	"fmt"
	"os"
	"strings"

	"github.com/jakelamon/keelix/internal/model"
)

// collectConfig is the pure framework that turns a file path + a parser into a
// model.ConfigFact. It stats the file (recording octal Mode), runs the parser,
// and sets SchemaKnown from the parser's verdict. When the parser reports the
// schema is unknown, Values is left empty so we never emit fabricated facts.
//
// Security hardening:
//   - The path must be on the allowlist; non-allowlisted paths return a bare fact.
//   - os.Lstat is used so symlinks are refused (not followed).
//   - Secret-bearing values are replaced with "[secret]" before storage.
//
// The parser signature matches the contract:
//
//	func(b []byte) (values map[string]string, schemaID string, known bool)
func collectConfig(path string, parse func([]byte) (map[string]string, string, bool)) model.ConfigFact {
	fact := model.ConfigFact{Source: path}

	// (i) Gate: only allowlisted paths may be read.
	if !isAllowed(path) {
		return fact
	}

	// (ii) Refuse symlinks — use Lstat so we inspect the link itself, not the target.
	linfo, err := os.Lstat(path)
	if err != nil {
		// Missing/unreadable: report a bare, unknown fact rather than a fake one.
		return fact
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		// Symlink — refuse to follow it.
		return fact
	}

	fact.Mode = fmt.Sprintf("%04o", linfo.Mode().Perm())

	b, err := os.ReadFile(path) // #nosec G304 -- path has passed the allowlist gate
	if err != nil {
		return fact
	}

	values, schemaID, known := parse(b)
	fact.SchemaID = schemaID
	fact.SchemaKnown = known
	if known {
		// (iii) Redact: replace secret-bearing values with a shape marker.
		fact.Values = redactConfigValues(values)
	}
	return fact
}

// collectConfigInternal is the framework core without the allowlist gate. It is
// used by tests that need to exercise parsing/redaction logic on testdata paths
// that are not on the production allowlist. Production callers must use
// collectConfig (which enforces the allowlist gate).
func collectConfigInternal(path string, parse func([]byte) (map[string]string, string, bool)) model.ConfigFact {
	fact := model.ConfigFact{Source: path}

	// Refuse symlinks — use Lstat so we inspect the link itself, not the target.
	linfo, err := os.Lstat(path)
	if err != nil {
		return fact
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return fact
	}

	fact.Mode = fmt.Sprintf("%04o", linfo.Mode().Perm())

	b, err := os.ReadFile(path) // #nosec G304 -- only called in tests with testdata paths
	if err != nil {
		return fact
	}

	values, schemaID, known := parse(b)
	fact.SchemaID = schemaID
	fact.SchemaKnown = known
	if known {
		fact.Values = redactConfigValues(values)
	}
	return fact
}

// credHeaderNames lists the HTTP header names that carry credentials.
// Matching is case-insensitive on the final dot-path segment.
var credHeaderNames = []string{
	"authorization", "x-api-key", "x-auth-token", "api-key", "apikey",
	"token", "secret", "password",
}

// isCredentialKeyPath reports whether the dotted key path k refers to a
// credential VALUE field that may legitimately hold a raw secret:
//
//   - any segment that is ".env." (e.g. mcpServers.foo.env.MY_KEY)
//   - any segment that is ".headers." (e.g. mcpServers.foo.headers.Authorization)
//   - the last segment matches a credential header name (case-insensitive)
//
// Structural fields — command, args.*, type, url — are explicitly excluded
// so package names and CLI args always reach checks verbatim.
func isCredentialKeyPath(k string) bool {
	lower := strings.ToLower(k)
	if strings.Contains(lower, ".env.") || strings.Contains(lower, ".headers.") {
		return true
	}
	// Check the last segment.
	last := lower
	if i := strings.LastIndex(lower, "."); i >= 0 {
		last = lower[i+1:]
	}
	for _, h := range credHeaderNames {
		if last == h {
			return true
		}
	}
	return false
}

// hasURLUserinfo reports whether v looks like a URL that embeds credentials in
// its userinfo component (scheme://user:pass@host). Only the structural
// colon-at-sign pattern is checked — no URL parsing — so this runs without
// extra imports. It matches any scheme followed by "://", a non-empty
// user:password pair, and "@".
func hasURLUserinfo(v string) bool {
	// Require "://" to identify URL-shaped values.
	slashSlash := strings.Index(v, "://")
	if slashSlash < 0 {
		return false
	}
	// The authority portion starts after "://".
	authority := v[slashSlash+3:]
	// A userinfo section ends at "@"; a password (":") must be present before it.
	at := strings.IndexByte(authority, '@')
	if at <= 0 {
		return false
	}
	userinfo := authority[:at]
	// Require at least one ":" separating user from password.
	colon := strings.IndexByte(userinfo, ':')
	// colon must not be the first character (empty username) and must not be
	// absent (no password). An empty password ("user:@host") is still a
	// credential pattern worth masking.
	return colon > 0
}

// redactConfigValues returns a copy of values where credential-field entries
// are replaced with a shape marker:
//
//   - "[keychain-ref]" when the value is a keychain/op://$ -ref
//   - "[secret]"       when classOf classifies the value as a secret, OR
//     when the value is a URL that embeds userinfo credentials
//     (scheme://user:pass@host) — this applies even to structural url fields
//     because the userinfo content is a raw credential regardless of key path.
//
// For dotted keys (MCP/agent JSON paths), only credential-field paths are
// eligible for masking — structural fields (command, args.*, type, url) are
// never masked so package specs and MCP addresses reach checks verbatim.
// Exception: a url-field value that contains embedded userinfo credentials IS
// masked to "[secret]" even though url is otherwise structural.
//
// For flat keys (no dots, e.g. dotenv variables), the original classOf
// behavior applies: any key whose name contains a secret token is masked.
func redactConfigValues(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for k, v := range values {
		isDotted := strings.Contains(k, ".")
		eligible := !isDotted || isCredentialKeyPath(k)
		if eligible {
			if keychainRef(v) {
				out[k] = "[keychain-ref]"
			} else if classOf(k, v) == "secret" {
				out[k] = "[secret]"
			} else {
				out[k] = v
			}
		} else {
			// Structural field (command, args.*, type, url …): pass through
			// verbatim UNLESS the value embeds URL userinfo credentials.
			if hasURLUserinfo(v) {
				out[k] = "[secret]"
			} else {
				out[k] = v
			}
		}
	}
	return out
}

// parseDotenv is the trivial example parser that exercises the framework. It
// reads KEY=VALUE lines (ignoring blanks and # comments). It reports the schema
// as known only when at least one valid KEY=VALUE line is present, so a binary
// or unrecognized file yields known=false and no fabricated values.
func parseDotenv(b []byte) (map[string]string, string, bool) {
	values := map[string]string{}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		if !isIdent(key) {
			continue
		}
		values[key] = strings.TrimSpace(line[i+1:])
	}
	if len(values) == 0 {
		return nil, "", false
	}
	return values, "dotenv", true
}

// isIdent reports whether s is a plausible env-style identifier.
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
