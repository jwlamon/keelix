package collect

import (
	"os"
	"path/filepath"

	"github.com/jakelamon/keelix/internal/model"
)

// configEntry maps an absolute path to its parser function.
type configEntry struct {
	Path   string
	Parser func([]byte) (map[string]string, string, bool)
}

// configPathTable returns the ordered list of AI-agent config file entries for
// the given home directory. Each entry pairs an absolute path with its parser.
// The function is exported to the package so tests can count expected entries.
func configPathTable(home string) []configEntry {
	j := filepath.Join
	return []configEntry{
		{j(home, ".openclaw", "openclaw.json"), parseOpenclawConfig},
		{j(home, ".openclaw", "exec-approvals.json"), parseOpenclawExecApprovals},
		{j(home, ".openclaw", "cron", "jobs.json"), parseOpenclawCron},
		{j(home, ".claude", "settings.json"), parseClaudeCodeSettings},
		{j(home, ".claude", "settings.local.json"), parseClaudeCodeSettings},
		{j(home, ".claude.json"), parseClaudeJSON},
		{j(home, ".codex", "config.toml"), parseCodexConfig},
		{j(home, ".codex", "config.json"), parseCodexConfig},
		{j(home, ".codex", "auth.json"), parseMCPJSON},
		// macOS Claude Desktop.
		{j(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), parseClaudeDesktopConfig},
		// Linux/XDG Claude Desktop.
		{j(home, ".config", "Claude", "claude_desktop_config.json"), parseClaudeDesktopConfig},
		// Cursor.
		{j(home, ".cursor", "mcp.json"), parseCursorMCP},
		// Windsurf.
		{j(home, ".codeium", "windsurf", "mcp_config.json"), parseWindsurfMCP},
	}
}

// collectConfigs iterates the AI-agent config path table and calls
// collectConfig (which enforces the allowlist gate) for each entry.
// Results are best-effort: missing or unreadable files produce bare facts,
// and the function never returns a non-nil error (failures are surfaced as
// bare facts with SchemaKnown=false). This matches the existing pattern used
// by the sockets/files/processes domains.
func collectConfigs(_ Options) ([]model.ConfigFact, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Cannot resolve home; return empty (not an error — missing agent configs
		// is a valid posture, not a collection failure).
		return []model.ConfigFact{}, nil
	}
	table := configPathTable(home)
	facts := make([]model.ConfigFact, 0, len(table))
	for _, e := range table {
		fact := collectConfig(e.Path, e.Parser)
		facts = append(facts, fact)
	}
	return facts, nil
}
