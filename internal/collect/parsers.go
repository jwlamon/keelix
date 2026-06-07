package collect

import (
	"encoding/json"
	"strconv"
	"strings"
)

// parseOpenclawConfig parses ~/.openclaw/openclaw.json.
// Required keys: tools.exec.security, tools.exec.ask, tools.profile,
// tools.fs.workspaceOnly, agents.defaults.sandbox.mode, browser.enabled,
// tools.web.search.provider, channels.discord.groupPolicy,
// channels.telegram.dmPolicy. Also emits any mcpServers.* present.
func parseOpenclawConfig(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	required := []string{
		"tools.exec.security", "tools.exec.ask",
		"tools.fs.workspaceOnly", "agents.defaults.sandbox.mode",
		"browser.enabled", "tools.web.search.provider",
		"channels.discord.groupPolicy", "channels.telegram.dmPolicy",
	}
	out := make(map[string]string)
	// Emit required keys (missing => empty string, still emitted so callers can
	// detect absence vs "off").
	for _, k := range required {
		out[k] = flat[k]
	}
	// tools.profile may be a top-level key or nested.
	if v, found := flat["tools.profile"]; found {
		out["tools.profile"] = v
	} else {
		out["tools.profile"] = flat["profile"]
	}
	// Emit all mcpServers.* keys present.
	for k, v := range flat {
		if len(k) > len("mcpServers.") && k[:len("mcpServers.")] == "mcpServers." {
			out[k] = v
		}
	}
	return out, "openclaw-config", true
}

// parseOpenclawExecApprovals parses ~/.openclaw/exec-approvals.json.
// Required keys: defaults.security, defaults.ask, defaults.askFallback.
func parseOpenclawExecApprovals(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	out := map[string]string{
		"defaults.security":    flat["defaults.security"],
		"defaults.ask":         flat["defaults.ask"],
		"defaults.askFallback": flat["defaults.askFallback"],
	}
	// Need at least one of the required keys to be non-empty to be "known".
	if out["defaults.ask"] == "" && out["defaults.security"] == "" {
		return nil, "", false
	}
	return out, "openclaw-exec-approvals", true
}

// parseOpenclawCron parses ~/.openclaw/cron/jobs.json.
// Emits: anyEnabled ("true"/"false"), jobsEnabledCount.
func parseOpenclawCron(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	// jobs is an array; flatten produces jobs.0.enabled, jobs.1.enabled, etc.
	enabledCount := 0
	for k, v := range flat {
		if len(k) > len("jobs.") && k[:len("jobs.")] == "jobs." {
			// Check for .enabled suffix.
			if len(k) > len(".enabled") && k[len(k)-len(".enabled"):] == ".enabled" {
				if v == "true" {
					enabledCount++
				}
			}
		}
	}
	anyEnabled := "false"
	if enabledCount > 0 {
		anyEnabled = "true"
	}
	out := map[string]string{
		"anyEnabled":       anyEnabled,
		"jobsEnabledCount": strconv.Itoa(enabledCount),
	}
	return out, "openclaw-cron", true
}

// parseMCPServersShape is the shared helper for any config file that uses the
// standard mcpServers.<name>.{command,args.<N>,env.<KEY>,url,type,headers.<KEY>}
// shape (claude-json, claude-desktop-config, cursor-mcp, windsurf-mcp).
func parseMCPServersShape(flat map[string]string) map[string]string {
	out := make(map[string]string)
	prefix := "mcpServers."
	for k, v := range flat {
		if len(k) <= len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		rest := k[len(prefix):]
		// rest = "<name>.<field>" or "<name>.args.<N>" etc.
		dot := len(rest)
		for i, c := range rest {
			if c == '.' {
				dot = i
				break
			}
		}
		if dot >= len(rest) {
			continue // no field separator
		}
		field := rest[dot+1:]
		// Allow: command, args.*, env.*, url, type, headers.*
		switch {
		case field == "command",
			field == "url",
			field == "type",
			len(field) > len("args.") && field[:len("args.")] == "args.",
			len(field) > len("env.") && field[:len("env.")] == "env.",
			len(field) > len("headers.") && field[:len("headers.")] == "headers.":
			out[k] = v
		}
	}
	return out
}

// keychainRef reports whether a value looks like a macOS Keychain reference
// (e.g. "keychain:<service>/<account>"), a 1Password secret-reference
// (op://<vault>/<item>/<field>), or an environment-variable reference that
// defers the secret to a shell variable ($VAR or ${VAR}).
// These are POSITIVE controls — they reference secrets rather than holding
// them — and must be emitted as "[keychain-ref]", never flagged as "[secret]".
func keychainRef(v string) bool {
	if len(v) > len("keychain:") && v[:len("keychain:")] == "keychain:" {
		return true
	}
	if len(v) > len("op://") && v[:len("op://")] == "op://" {
		return true
	}
	// $VAR or ${VAR}: an env-variable reference defers the secret to the
	// calling shell — the config file holds a reference, not a raw credential.
	if len(v) > 1 && v[0] == '$' {
		return true
	}
	return false
}

// parseClaudeCodeSettings parses ~/.claude/settings.json and
// ~/.claude/settings.local.json.
// Emits: defaultMode, skipDangerousModePermissionPrompt,
// permissions.allow.<N> (array elements), and any mcpServers.* present.
func parseClaudeCodeSettings(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	out := make(map[string]string)
	for _, k := range []string{"defaultMode", "skipDangerousModePermissionPrompt"} {
		if v, found := flat[k]; found {
			out[k] = v
		} else {
			out[k] = ""
		}
	}
	// Emit permissions.allow array elements.
	allowPrefix := "permissions.allow."
	for k, v := range flat {
		if len(k) > len(allowPrefix) && k[:len(allowPrefix)] == allowPrefix {
			out[k] = v
		}
	}
	// Emit mcpServers.* shape keys.
	for k, v := range parseMCPServersShape(flat) {
		out[k] = v
	}
	return out, "claude-code-settings", true
}

// parseClaudeJSON parses ~/.claude.json (the user-level Claude desktop
// settings that may hold bypassPermissionsModeEnabled and mcpServers).
func parseClaudeJSON(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	out := make(map[string]string)
	for _, k := range []string{
		"bypassPermissionsModeEnabled",
		"allowAllBrowserActions",
	} {
		if v, found := flat[k]; found {
			out[k] = v
		} else {
			out[k] = ""
		}
	}
	for k, v := range parseMCPServersShape(flat) {
		out[k] = v
	}
	if len(out) == 2 && out["bypassPermissionsModeEnabled"] == "" && out["allowAllBrowserActions"] == "" {
		// Nothing useful extracted — consider unknown.
		return nil, "", false
	}
	return out, "claude-json", true
}

// parseCodexConfig parses ~/.codex/config.toml and ~/.codex/config.json.
// For TOML it uses a minimal key=value reader (Codex uses simple top-level keys).
// For JSON it falls back to flattenJSON.
// Emits: approval_policy, sandbox_mode.
func parseCodexConfig(b []byte) (map[string]string, string, bool) {
	// Try JSON first.
	if flat, ok := flattenJSON(b); ok {
		out := map[string]string{
			"approval_policy": flat["approval_policy"],
			"sandbox_mode":    flat["sandbox_mode"],
		}
		if out["approval_policy"] == "" && out["sandbox_mode"] == "" {
			return nil, "", false
		}
		return out, "codex-config", true
	}
	// Minimal TOML key=value reader for simple top-level keys.
	flat := parseMinimalTOML(b)
	out := map[string]string{
		"approval_policy": flat["approval_policy"],
		"sandbox_mode":    flat["sandbox_mode"],
	}
	if out["approval_policy"] == "" && out["sandbox_mode"] == "" {
		return nil, "", false
	}
	return out, "codex-config", true
}

// parseMinimalTOML reads simple top-level key = "value" or key = value lines
// from a TOML file. It is intentionally minimal — Codex uses only simple
// top-level string/bool keys. Section headers ([section]) and complex values
// are ignored.
//
// Inline comments are stripped:
//   - For a quoted value, everything after the closing quote is discarded.
//   - For a bare value, everything from the first '#' character is discarded.
func parseMinimalTOML(b []byte) map[string]string {
	out := make(map[string]string)
	lines := splitLines(string(b))
	for _, raw := range lines {
		line := trimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == '[' {
			continue
		}
		eq := indexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := trimSpace(line[:eq])
		val := trimSpace(line[eq+1:])
		if len(val) >= 2 && val[0] == '"' {
			// Quoted string: find the closing quote and discard everything after it.
			close := indexByte(val[1:], '"')
			if close >= 0 {
				// close is relative to val[1:], so the closing quote is at val[1+close].
				val = val[1 : 1+close]
			}
			// If no closing quote is found, fall through with the raw value
			// (malformed TOML — best effort).
		} else {
			// Bare value: drop from the first '#' character (inline comment).
			if hash := indexByte(val, '#'); hash >= 0 {
				val = trimSpace(val[:hash])
			}
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// parseClaudeDesktopConfig parses claude_desktop_config.json (macOS and Linux).
// Emits: mcpServers shape, preferences.bypassPermissionsModeEnabled,
// preferences.allowAllBrowserActions,
// preferences.localAgentModeTrustedFolders.<N>.
func parseClaudeDesktopConfig(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	out := make(map[string]string)
	for k, v := range parseMCPServersShape(flat) {
		out[k] = v
	}
	for _, k := range []string{
		"preferences.bypassPermissionsModeEnabled",
		"preferences.allowAllBrowserActions",
	} {
		if v, found := flat[k]; found {
			out[k] = v
		} else {
			out[k] = ""
		}
	}
	// Emit trustedFolders array.
	tfPrefix := "preferences.localAgentModeTrustedFolders."
	for k, v := range flat {
		if len(k) > len(tfPrefix) && k[:len(tfPrefix)] == tfPrefix {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, "", false
	}
	return out, "claude-desktop-config", true
}

// parseMCPJSON parses generic MCP JSON files (mcp.json, cursor mcp.json, etc.)
// that use the mcpServers.<name>.{command,args,env,url,type,headers} shape.
func parseMCPJSON(b []byte) (map[string]string, string, bool) {
	flat, ok := flattenJSON(b)
	if !ok {
		return nil, "", false
	}
	out := parseMCPServersShape(flat)
	if len(out) == 0 {
		return nil, "", false
	}
	return out, "mcp-json", true
}

// parseCursorMCP parses ~/.cursor/mcp.json using the same MCP servers shape.
func parseCursorMCP(b []byte) (map[string]string, string, bool) {
	vals, _, known := parseMCPJSON(b)
	if !known {
		return nil, "", false
	}
	return vals, "cursor-mcp", true
}

// parseWindsurfMCP parses ~/.codeium/windsurf/mcp_config.json.
func parseWindsurfMCP(b []byte) (map[string]string, string, bool) {
	vals, _, known := parseMCPJSON(b)
	if !known {
		return nil, "", false
	}
	return vals, "windsurf-mcp", true
}

// parseDockerDaemon parses /etc/docker/daemon.json and extracts the "hosts"
// field as a comma-joined list. SchemaID = "docker-daemon", key = "hosts".
func parseDockerDaemon(b []byte) (map[string]string, string, bool) {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, "", false
	}
	hostsVal, ok := raw["hosts"]
	if !ok {
		// File is valid daemon.json but has no "hosts" key — emit known schema
		// with empty hosts so the check can distinguish "not configured" from
		// "file not found".
		return map[string]string{"hosts": ""}, "docker-daemon", true
	}
	var parts []string
	switch v := hostsVal.(type) {
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
	case string:
		if v != "" {
			parts = append(parts, v)
		}
	}
	return map[string]string{"hosts": strings.Join(parts, ",")}, "docker-daemon", true
}

// --- minimal string helpers to avoid extra imports ---

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// keychainRef is called by redactConfigValues in config.go to detect
// secret-store references (keychain:, op://) that must be emitted as
// "[keychain-ref]" rather than "[secret]" or the raw value.
