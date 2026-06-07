package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"exact-docker-daemon", "/etc/docker/daemon.json", true},
		{"exact-ssh-config", "/etc/ssh/sshd_config", true},
		{"prefix-ssh-config-d", "/etc/ssh/sshd_config.d/50-cloud.conf", true},
		{"prefix-docker-dir", "/etc/docker/key.json", true},
		{"now-allowed-passwd", "/etc/passwd", true}, // SP2 added /etc/passwd to allowlist
		{"not-allowed-home", "/home/lars/.ssh/id_rsa", false},
		{"empty", "", false},
		{"traversal-blocked", "/etc/docker/../../etc/passwd", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAllowed(tt.path); got != tt.want {
				t.Errorf("isAllowed(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestAllowlistNonEmpty(t *testing.T) {
	if len(allowlist) == 0 {
		t.Fatal("allowlist must not be empty")
	}
}

func TestAllowlist_SP2StaticPaths(t *testing.T) {
	sp2Paths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/login.defs",
		"/etc/os-release",
		// prefix entries: any file under the directory
		"/etc/apt/apt.conf.d/20auto-upgrades",
		"/etc/apt/apt.conf.d/50unattended-upgrades",
		"/etc/fail2ban/jail.conf",
		"/etc/crontab",
		"/etc/cron.d/mycron",
	}
	for _, p := range sp2Paths {
		if !isAllowed(p) {
			t.Errorf("isAllowed(%q) = false, want true", p)
		}
	}
}

func TestIsAllowedHomeRelative(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir: %v", err)
	}

	allowed := []string{
		filepath.Join(home, ".openclaw", "openclaw.json"),
		filepath.Join(home, ".openclaw", "exec-approvals.json"),
		filepath.Join(home, ".openclaw", "cron", "jobs.json"),
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".codex", "config.toml"),
		filepath.Join(home, ".codex", "config.json"),
		filepath.Join(home, ".codex", "auth.json"),
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"),
	}
	for _, p := range allowed {
		if !isAllowed(p) {
			t.Errorf("isAllowed(%q) = false, want true", p)
		}
	}

	// A path in ~ that is NOT on the list must still be rejected.
	notAllowed := filepath.Join(home, ".ssh", "id_rsa")
	if isAllowed(notAllowed) {
		t.Errorf("isAllowed(%q) = true, want false (not on home allowlist)", notAllowed)
	}
}
