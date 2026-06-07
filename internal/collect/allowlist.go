package collect

import (
	"os"
	"path/filepath"
	"strings"
)

// allowEntry is one allowlist rule. When Prefix is true, any path under Path
// (a directory) is allowed; otherwise only an exact match is allowed.
// When Home is true, Path is resolved relative to os.UserHomeDir() at
// init time; absolute paths (Home=false) are used as-is.
// When Prefix is true, MaxDepth constrains the subtree walk to that number of
// levels (0 means the global walkMaxDepth applies).
// When WalkOnly is true, the entry is used for the collectFiles subtree walk
// but is NOT considered by isAllowed — it does not permit arbitrary reads.
type allowEntry struct {
	Path     string
	Prefix   bool
	Home     bool
	MaxDepth int  // only consulted when Prefix=true; 0 → use walkMaxDepth
	WalkOnly bool // walk for FileFacts only; excluded from isAllowed
}

// staticAllowlist is the PINNED set of absolute security-relevant paths.
var staticAllowlist = []allowEntry{
	{Path: "/etc/docker/daemon.json"},
	{Path: "/etc/docker", Prefix: true},
	{Path: "/etc/ssh/sshd_config"},
	{Path: "/etc/ssh/sshd_config.d", Prefix: true},
	{Path: "/etc/sudoers"},
	{Path: "/etc/sudoers.d", Prefix: true},
	{Path: "/etc/nginx/nginx.conf"},
	{Path: "/etc/nginx/conf.d", Prefix: true},
	{Path: "/etc/caddy/Caddyfile"},
	{Path: "/etc/traefik/traefik.yml"},
	{Path: "/var/run/docker.sock"},
	// NFS host service config (FIX-1: SVC041 reachability).
	{Path: "/etc/exports"},
	// SP2 host-OS posture paths.
	{Path: "/etc/passwd"},
	{Path: "/etc/shadow"},
	{Path: "/etc/login.defs"},
	{Path: "/etc/os-release"},
	{Path: "/etc/apt/apt.conf.d", Prefix: true},
	{Path: "/etc/fail2ban", Prefix: true},
	{Path: "/etc/crontab"},
	{Path: "/etc/cron.d", Prefix: true},
}

// homeRelativeEntries is the pinned set of HOME-relative paths for AI-agent
// config files. Paths are resolved to absolute at init time via
// os.UserHomeDir(); if that call fails, the home entries are silently omitted
// (no host path is readable through an unresolved entry).
//
// Prefix entries (Prefix:true) mark directories whose entire subtree should be
// walked by collectFiles (bounded depth/count). They enable AGT005 (backup
// sprawl in config dirs) and AGT010 (unpinned git-backed extensions).
var homeRelativeEntries = []allowEntry{
	{Path: ".openclaw/openclaw.json", Home: true},
	{Path: ".openclaw/exec-approvals.json", Home: true},
	{Path: ".openclaw/cron/jobs.json", Home: true},
	// Prefix entries for extension/skill/plugin subtrees (AGT010) and backup
	// sprawl siblings (AGT005). Subtree walks are bounded in collectFiles.
	{Path: ".openclaw/extensions", Home: true, Prefix: true},
	{Path: ".openclaw/skills", Home: true, Prefix: true},
	{Path: ".openclaw/plugins", Home: true, Prefix: true},
	// Depth-1 walk of ~/.openclaw finds *.json.bak siblings of the canonical files.
	{Path: ".openclaw", Home: true, Prefix: true, MaxDepth: 1},
	{Path: ".claude/settings.json", Home: true},
	{Path: ".claude/settings.local.json", Home: true},
	{Path: ".claude.json", Home: true},
	// Parent config dirs — walked so *.bak siblings of the canonical files are
	// stat'd by AGT005. Depth-1 walk of ~/.claude is sufficient for siblings;
	// deep walks (default depth) cover skills/plugins subdirs for AGT010.
	{Path: ".claude", Home: true, Prefix: true, MaxDepth: 1},
	{Path: ".claude/skills", Home: true, Prefix: true},
	{Path: ".claude/plugins", Home: true, Prefix: true},
	// Depth-1 walk of HOME captures *.bak backups of ~/.claude.json and
	// other home-root agent config files (e.g. ~/.claude.json.bak).
	// WalkOnly: does NOT widen isAllowed — only used by the file walker.
	{Path: ".", Home: true, Prefix: true, MaxDepth: 1, WalkOnly: true},
	{Path: ".codex/config.toml", Home: true},
	{Path: ".codex/config.json", Home: true},
	{Path: ".codex/auth.json", Home: true},
	// macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
	{Path: "Library/Application Support/Claude/claude_desktop_config.json", Home: true},
	// Linux/XDG: ~/.config/Claude/claude_desktop_config.json
	{Path: ".config/Claude/claude_desktop_config.json", Home: true},
	{Path: ".cursor/mcp.json", Home: true},
	{Path: ".codeium/windsurf/mcp_config.json", Home: true},
}

// allowlist is the resolved merged allowlist, built once at package init.
var allowlist []allowEntry

func init() {
	allowlist = append(allowlist, staticAllowlist...)
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Cannot resolve home; skip home-relative entries rather than allow nothing
		// or panic. The collector will fail gracefully on missing paths.
		return
	}
	for _, e := range homeRelativeEntries {
		abs := filepath.Join(home, e.Path)
		allowlist = append(allowlist, allowEntry{Path: abs, Prefix: e.Prefix, MaxDepth: e.MaxDepth, WalkOnly: e.WalkOnly})
	}
}

// buildHomeAllowlist constructs the resolved allowlist for the given home dir.
// It is shared by init, rebuildAllowlistForHome, and rebuildAllowlistForDefaultHome.
func buildHomeAllowlist(home string) []allowEntry {
	out := make([]allowEntry, 0, len(staticAllowlist)+len(homeRelativeEntries))
	out = append(out, staticAllowlist...)
	for _, e := range homeRelativeEntries {
		abs := filepath.Join(home, e.Path)
		out = append(out, allowEntry{Path: abs, Prefix: e.Prefix, MaxDepth: e.MaxDepth, WalkOnly: e.WalkOnly})
	}
	return out
}

// rebuildAllowlistForHome rebuilds the package-level allowlist using the given
// home directory instead of os.UserHomeDir(). It is only called from tests
// that need to point the allowlist at a temp directory.
func rebuildAllowlistForHome(home string) {
	allowlist = buildHomeAllowlist(home)
}

// rebuildAllowlistForDefaultHome rebuilds the package-level allowlist using
// the real os.UserHomeDir(). Tests call this in t.Cleanup to restore state.
func rebuildAllowlistForDefaultHome() {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		allowlist = append([]allowEntry{}, staticAllowlist...)
		return
	}
	allowlist = buildHomeAllowlist(home)
}

// RebuildAllowlistForHome is the exported test-support entry point for
// packages outside internal/collect that need to redirect the allowlist at a
// temp home directory (e.g. checks/aiagent parser-fed regression tests).
func RebuildAllowlistForHome(home string) { rebuildAllowlistForHome(home) }

// RebuildAllowlistForDefaultHome is the exported test-support entry point for
// packages outside internal/collect that restore the allowlist to the real
// os.UserHomeDir() in a t.Cleanup callback.
func RebuildAllowlistForDefaultHome() { rebuildAllowlistForDefaultHome() }

// isAllowed reports whether path is permitted by the pinned allowlist. The
// path is first cleaned; any path that is not absolute after cleaning, or that
// escaped via ".." traversal, is rejected.
func isAllowed(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return false
	}
	// Reject anything that still differs from a no-traversal cleaning, i.e. the
	// caller tried to escape via "..".
	if clean != path && strings.Contains(path, "..") {
		return false
	}
	for _, e := range allowlist {
		if e.WalkOnly {
			// Walk-only entries drive the file walker but do not widen the
			// config-read gate — skip them here.
			continue
		}
		if e.Prefix {
			if clean == e.Path || strings.HasPrefix(clean, e.Path+string(filepath.Separator)) {
				return true
			}
			continue
		}
		if clean == e.Path {
			return true
		}
	}
	return false
}
