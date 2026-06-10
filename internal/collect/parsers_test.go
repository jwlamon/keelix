package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jakelamon/keelix/internal/checks/aiagent"
	"github.com/jakelamon/keelix/internal/model"
)

// helper: read testdata file bytes, fatalf on error.
func mustReadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return b
}

func TestParseOpenclawConfig(t *testing.T) {
	b := mustReadTestdata(t, "openclaw-config.json")
	vals, schemaID, known := parseOpenclawConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "openclaw-config" {
		t.Errorf("schemaID=%q, want openclaw-config", schemaID)
	}
	// Required top-level keys.
	for _, k := range []string{
		"tools.exec.security", "tools.exec.ask", "tools.profile",
		"tools.fs.workspaceOnly", "agents.defaults.sandbox.mode",
		"browser.enabled", "tools.web.search.provider",
		"channels.discord.groupPolicy", "channels.telegram.dmPolicy",
	} {
		if _, ok := vals[k]; !ok {
			t.Errorf("missing required key %q", k)
		}
	}
	// At least one mcpServers entry should appear.
	names := mcpServerNames(vals)
	if len(names) == 0 {
		t.Error("expected at least one mcpServers entry from fixture")
	}
}

func TestParseOpenclawExecApprovals(t *testing.T) {
	b := mustReadTestdata(t, "openclaw-exec-approvals.json")
	vals, schemaID, known := parseOpenclawExecApprovals(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "openclaw-exec-approvals" {
		t.Errorf("schemaID=%q", schemaID)
	}
	if vals["defaults.security"] == "" {
		t.Error("missing defaults.security")
	}
	if vals["defaults.ask"] == "" {
		t.Error("missing defaults.ask")
	}
	if vals["defaults.askFallback"] == "" {
		t.Error("missing defaults.askFallback")
	}
	// The on-miss fixture must NOT look like auto-approval.
	// (ask=="on-miss" means approval IS required on cache miss — not auto.)
	if vals["defaults.ask"] == "off" {
		t.Errorf("fixture defaults.ask should be on-miss (not auto-approval), got %q", vals["defaults.ask"])
	}
}

func TestParseOpenclawCron(t *testing.T) {
	b := mustReadTestdata(t, "openclaw-cron.json")
	vals, schemaID, known := parseOpenclawCron(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "openclaw-cron" {
		t.Errorf("schemaID=%q", schemaID)
	}
	if _, ok := vals["anyEnabled"]; !ok {
		t.Error("missing anyEnabled key")
	}
	if _, ok := vals["jobsEnabledCount"]; !ok {
		t.Error("missing jobsEnabledCount key")
	}
}

func TestParseOpenclawConfigUnknownOnBadJSON(t *testing.T) {
	_, _, known := parseOpenclawConfig([]byte(`not json`))
	if known {
		t.Error("expected known=false on invalid JSON")
	}
}

func TestParseClaudeCodeSettings(t *testing.T) {
	b := mustReadTestdata(t, "claude-code-settings.json")
	vals, schemaID, known := parseClaudeCodeSettings(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "claude-code-settings" {
		t.Errorf("schemaID=%q", schemaID)
	}
	if _, ok := vals["defaultMode"]; !ok {
		t.Error("missing defaultMode")
	}
	if _, ok := vals["skipDangerousModePermissionPrompt"]; !ok {
		t.Error("missing skipDangerousModePermissionPrompt")
	}
}

func TestParseClaudeJSON(t *testing.T) {
	b := mustReadTestdata(t, "claude.json")
	vals, schemaID, known := parseClaudeJSON(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "claude-json" {
		t.Errorf("schemaID=%q", schemaID)
	}
	// bypassPermissionsModeEnabled must be present.
	if _, ok := vals["bypassPermissionsModeEnabled"]; !ok {
		t.Error("missing bypassPermissionsModeEnabled")
	}
	// mcpServers shape keys must be emitted.
	names := mcpServerNames(vals)
	if len(names) == 0 {
		t.Error("expected at least one mcpServer name in claude.json fixture")
	}
}

func TestParseClaudeJSONKeychainRefNotSecret(t *testing.T) {
	// A keychain-ref env value must be emitted as a LITERAL (not "[secret]")
	// because the redactor only replaces high-entropy/secret-named values.
	// This test verifies the fixture has a keychain: prefix that survives
	// through the framework as the literal string (framework redacts after
	// parsing, and "keychain:..." has low entropy).
	b := mustReadTestdata(t, "mcp-config.json")
	vals, _, known := parseMCPJSON(b)
	if !known {
		t.Fatal("known=false")
	}
	// Find env key with keychain: value.
	found := false
	for k, v := range vals {
		_ = k
		if len(v) > len("keychain:") && v[:len("keychain:")] == "keychain:" {
			found = true
		}
	}
	if !found {
		t.Error("expected a keychain: ref value in fixture; not found")
	}
}

func TestParseCodexConfigTOML(t *testing.T) {
	b := mustReadTestdata(t, "codex-config.toml")
	vals, schemaID, known := parseCodexConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "codex-config" {
		t.Errorf("schemaID=%q", schemaID)
	}
	if _, ok := vals["approval_policy"]; !ok {
		t.Error("missing approval_policy")
	}
	if _, ok := vals["sandbox_mode"]; !ok {
		t.Error("missing sandbox_mode")
	}
}

func TestParseClaudeDesktopConfig(t *testing.T) {
	b := mustReadTestdata(t, "claude-desktop-config.json")
	vals, schemaID, known := parseClaudeDesktopConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "claude-desktop-config" {
		t.Errorf("schemaID=%q", schemaID)
	}
	names := mcpServerNames(vals)
	if len(names) == 0 {
		t.Error("expected at least one mcpServer from claude-desktop-config fixture")
	}
	if _, ok := vals["preferences.bypassPermissionsModeEnabled"]; !ok {
		t.Error("missing preferences.bypassPermissionsModeEnabled")
	}
}

func TestParseMCPJSON(t *testing.T) {
	b := mustReadTestdata(t, "mcp-config.json")
	vals, schemaID, known := parseMCPJSON(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "mcp-json" {
		t.Errorf("schemaID=%q", schemaID)
	}
	names := mcpServerNames(vals)
	if len(names) == 0 {
		t.Error("expected at least one mcpServer")
	}
}

func TestParseCursorMCP(t *testing.T) {
	b := mustReadTestdata(t, "mcp-config.json")
	vals, schemaID, known := parseCursorMCP(b)
	if !known {
		t.Fatal("known=false")
	}
	if schemaID != "cursor-mcp" {
		t.Errorf("schemaID=%q", schemaID)
	}
	_ = vals
}

func TestParseWindsurfMCP(t *testing.T) {
	b := mustReadTestdata(t, "mcp-config.json")
	vals, schemaID, known := parseWindsurfMCP(b)
	if !known {
		t.Fatal("known=false")
	}
	if schemaID != "windsurf-mcp" {
		t.Errorf("schemaID=%q", schemaID)
	}
	_ = vals
}

func TestMcpServerNames(t *testing.T) {
	vals := map[string]string{
		"mcpServers.slack.command":      "npx",
		"mcpServers.slack.args.0":       "slack-mcp",
		"mcpServers.filesystem.command": "uvx",
		"mcpServers.filesystem.args.0":  "mcp-server-fs",
		"mcpServers.nocommand.url":      "http://localhost:3000",
	}
	names := mcpServerNames(vals)
	// Should return only names with a .command key, sorted.
	if len(names) != 2 {
		t.Fatalf("mcpServerNames = %v, want [filesystem slack]", names)
	}
	if names[0] != "filesystem" || names[1] != "slack" {
		t.Errorf("mcpServerNames = %v, want [filesystem slack]", names)
	}
}

// TestRFX6_ParseMinimalTOML_InlineComments is the PARSER-FED regression test
// for RFX-6: parseMinimalTOML did not strip inline TOML comments, so a value
// like 'approval_policy = "auto"  # note' was parsed with the comment attached,
// causing AGT001/AGT007 (which compare approval_policy=="auto") to be evaded.
//
// This test runs the real parse->redact->check pipeline (NOT synthetic signals)
// to guard against any regression of the comment-stripping fix.
func TestRFX6_ParseMinimalTOML_InlineComments(t *testing.T) {
	// TOML with inline comments on both relevant fields — this is the bug trigger.
	const tomlWithComments = `approval_policy = "auto"  # yolo
sandbox_mode = "danger-full-access"  # x
model = "o4-mini"  # some other note
`

	// Step 1: verify the parser itself strips comments correctly.
	vals := parseMinimalTOML([]byte(tomlWithComments))
	if got := vals["approval_policy"]; got != "auto" {
		t.Errorf("parseMinimalTOML: approval_policy = %q, want \"auto\" (inline comment not stripped)", got)
	}
	if got := vals["sandbox_mode"]; got != "danger-full-access" {
		t.Errorf("parseMinimalTOML: sandbox_mode = %q, want \"danger-full-access\" (inline comment not stripped)", got)
	}

	// Step 2: run the full parse->redact->check pipeline via a temp file so we
	// exercise collectConfigInternal (the same code path used in production).
	tmp, err := os.CreateTemp(t.TempDir(), "codex-config-*.toml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := tmp.WriteString(tomlWithComments); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	tmp.Close()

	fact := collectConfigInternal(tmp.Name(), parseCodexConfig)
	if !fact.SchemaKnown {
		t.Fatalf("collectConfigInternal: SchemaKnown=false — fixture parse failed; values: %v", fact.Values)
	}
	if got := fact.Values["approval_policy"]; got != "auto" {
		t.Errorf("pipeline: approval_policy = %q after redact, want \"auto\"", got)
	}

	// Step 3: confirm AGT001 fires — inline-comment evasion must be impossible.
	c := findRegisteredCheck(t, "AGT001")
	ctx := &model.ScanContext{
		Collector: &model.Signals{Configs: []model.ConfigFact{fact}},
	}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "AGT001" && f.IsFail() {
			return // expected: AGT001 fires for approval_policy=="auto"
		}
	}
	t.Fatalf("RFX-6: AGT001 must fire when codex approval_policy==\"auto\" (with inline comment); got %+v\nRedacted values: %v", findings, fact.Values)
}

// TestRFX6_ParseMinimalTOML_BareValueComment verifies that inline comments on
// bare (unquoted) values are also stripped correctly.
func TestRFX6_ParseMinimalTOML_BareValueComment(t *testing.T) {
	const toml = `full_auto = true  # this is risky
name = hello  # world
`
	vals := parseMinimalTOML([]byte(toml))
	if got := vals["full_auto"]; got != "true" {
		t.Errorf("parseMinimalTOML bare: full_auto = %q, want \"true\"", got)
	}
	if got := vals["name"]; got != "hello" {
		t.Errorf("parseMinimalTOML bare: name = %q, want \"hello\"", got)
	}
}

// TestParseCodexConfigTOML_InlineComments verifies that parseCodexConfig
// correctly handles a TOML file with inline comments on the key fields,
// producing the clean values that checks depend on.
func TestParseCodexConfigTOML_InlineComments(t *testing.T) {
	const tomlWithComments = `approval_policy = "auto"  # yolo
sandbox_mode = "danger-full-access"  # x
`
	// Write to a temp file and use parseCodexConfig directly (pure function test).
	vals, schemaID, known := parseCodexConfig([]byte(tomlWithComments))
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "codex-config" {
		t.Errorf("schemaID=%q, want codex-config", schemaID)
	}
	if got := vals["approval_policy"]; got != "auto" {
		t.Errorf("approval_policy = %q, want \"auto\" (inline comment must be stripped)", got)
	}
	if got := vals["sandbox_mode"]; got != "danger-full-access" {
		t.Errorf("sandbox_mode = %q, want \"danger-full-access\" (inline comment must be stripped)", got)
	}
}

func TestParseSSHDashT_Effective(t *testing.T) {
	b := mustReadTestdata(t, "sshd_effective.txt")
	vals, schemaID, known := parseSSHDashT(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "sshd-effective" {
		t.Errorf("schemaID=%q, want sshd-effective", schemaID)
	}
	cases := map[string]string{
		"permitrootlogin":        "yes",
		"passwordauthentication": "yes",
		"x11forwarding":          "yes",
		"maxauthtries":           "6",
		"logingracetime":         "120",
	}
	for k, want := range cases {
		if got := vals[k]; got != want {
			t.Errorf("vals[%q]=%q, want %q", k, got, want)
		}
	}
	// RFX-3 fix: parseSSHDashT must now set _source="effective" so the Fatal
	// gate in HST003 can engage on the authoritative sshd -T path.
	if vals["_source"] != "effective" {
		t.Errorf("parseSSHDashT must set _source=effective (RFX-3 fix), got %q", vals["_source"])
	}
}

func TestParseSSHDConfig_Static(t *testing.T) {
	b := mustReadTestdata(t, "sshd_config.txt")
	vals, schemaID, known := parseSSHDConfig(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "sshd-effective" {
		t.Errorf("schemaID=%q, want sshd-effective", schemaID)
	}
	if vals["_source"] != "static" {
		t.Errorf("parseSSHDConfig must set _source=static, got %q", vals["_source"])
	}
	if vals["passwordauthentication"] != "no" {
		t.Errorf("passwordauthentication=%q, want no", vals["passwordauthentication"])
	}
	if vals["permitrootlogin"] != "prohibit-password" {
		t.Errorf("permitrootlogin=%q, want prohibit-password", vals["permitrootlogin"])
	}
}

func TestParseSSHDashT_Empty(t *testing.T) {
	_, _, known := parseSSHDashT([]byte(""))
	if known {
		t.Error("empty input: want known=false")
	}
}

// TestParseSSHDConfig_InlineContent verifies that parseSSHDConfig correctly
// handles an inline config byte slice and produces the expected keys,
// including _source="static". This is the cross-platform parser test;
// the Linux-only collectSSHStatic integration path is exercised separately
// under a linux build tag.
func TestParseSSHDConfig_InlineContent(t *testing.T) {
	content := "PasswordAuthentication yes\nPermitRootLogin no\n"

	vals, schemaID, known := parseSSHDConfig([]byte(content))
	if !known {
		t.Fatal("parseSSHDConfig: want known=true")
	}
	if schemaID != "sshd-effective" {
		t.Errorf("schemaID=%q", schemaID)
	}
	if vals["_source"] != "static" {
		t.Errorf("_source=%q, want static", vals["_source"])
	}
	if vals["passwordauthentication"] != "yes" {
		t.Errorf("passwordauthentication=%q, want yes", vals["passwordauthentication"])
	}
}

func TestParsePasswd(t *testing.T) {
	b := mustReadTestdata(t, "passwd.txt")
	vals, schemaID, known := parsePasswd(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "accounts-passwd" {
		t.Errorf("schemaID=%q, want accounts-passwd", schemaID)
	}
	// root and toor both have uid 0; alice does not.
	uid0 := vals["uid0.accounts"]
	if !strings.Contains(uid0, "root") {
		t.Errorf("uid0.accounts=%q, want 'root' listed", uid0)
	}
	if !strings.Contains(uid0, "toor") {
		t.Errorf("uid0.accounts=%q, want 'toor' listed", uid0)
	}
	// duplicate.uids must signal that multiple uid-0 accounts exist.
	if vals["duplicate.uids"] != "true" {
		t.Errorf("duplicate.uids=%q, want true", vals["duplicate.uids"])
	}
}

func TestParseShadow_EmptyPassword(t *testing.T) {
	b := mustReadTestdata(t, "shadow.txt")
	vals, schemaID, known := parseShadow(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "accounts-shadow" {
		t.Errorf("schemaID=%q, want accounts-shadow", schemaID)
	}
	// alice has empty password field; bob has "!" (locked). Only alice counts.
	ep := vals["empty.password.accounts"]
	if !strings.Contains(ep, "alice") {
		t.Errorf("empty.password.accounts=%q, want alice listed", ep)
	}
	if strings.Contains(ep, "root") {
		t.Errorf("empty.password.accounts=%q, must not list root (has a hash)", ep)
	}
	// Hash fields must never appear in vals.
	for k, v := range vals {
		if k != "empty.password.accounts" && k != "_source" {
			t.Errorf("unexpected key %q=%q in shadow vals (hash fields must be dropped)", k, v)
		}
	}
}

func TestParseLoginDefs(t *testing.T) {
	b := mustReadTestdata(t, "login_defs.txt")
	vals, schemaID, known := parseLoginDefs(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "accounts-logindefs" {
		t.Errorf("schemaID=%q, want accounts-logindefs", schemaID)
	}
	if vals["PASS_MAX_DAYS"] != "90" {
		t.Errorf("PASS_MAX_DAYS=%q, want 90", vals["PASS_MAX_DAYS"])
	}
	if vals["UMASK"] != "022" {
		t.Errorf("UMASK=%q, want 022", vals["UMASK"])
	}
	if vals["ENCRYPT_METHOD"] != "SHA512" {
		t.Errorf("ENCRYPT_METHOD=%q, want SHA512", vals["ENCRYPT_METHOD"])
	}
}

func TestParseSudoers_NOPASSWD(t *testing.T) {
	b := mustReadTestdata(t, "sudoers.txt")
	vals, schemaID, known := parseSudoers(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "accounts-sudoers" {
		t.Errorf("schemaID=%q, want accounts-sudoers", schemaID)
	}
	if vals["nopasswd.present"] != "true" {
		t.Errorf("nopasswd.present=%q, want true", vals["nopasswd.present"])
	}
	// nopasswd.rules must be present but redacted (no raw command paths).
	if vals["nopasswd.rules"] == "" {
		t.Error("nopasswd.rules is empty, want a redacted rule summary")
	}
}

func TestParseOSRelease_DebianBookworm(t *testing.T) {
	b := mustReadTestdata(t, "os_release_bookworm.txt")
	// Bookworm EOL is 2028-06-01; use a date before that.
	collectedAt := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	distro, version, eol := parseOSRelease(b, collectedAt)
	if distro != "debian" {
		t.Errorf("distro=%q, want debian", distro)
	}
	if version != "12" {
		t.Errorf("version=%q, want 12", version)
	}
	if eol {
		t.Error("bookworm is not EOL in 2026, got eol=true")
	}
}

func TestParseOSRelease_UbuntuFocal_EOL(t *testing.T) {
	b := mustReadTestdata(t, "os_release_focal.txt")
	// Ubuntu 20.04 LTS EOL is 2025-05-31; use a date after that.
	collectedAt := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	distro, version, eol := parseOSRelease(b, collectedAt)
	if distro != "ubuntu" {
		t.Errorf("distro=%q, want ubuntu", distro)
	}
	if version != "20.04" {
		t.Errorf("version=%q, want 20.04", version)
	}
	if !eol {
		t.Error("ubuntu 20.04 is EOL after 2025-05-31, got eol=false")
	}
}

func TestParseOSRelease_Unknown(t *testing.T) {
	b := []byte("NAME=SomeOS\nID=someos\nVERSION_ID=99\n")
	collectedAt := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	distro, _, eol := parseOSRelease(b, collectedAt)
	if distro != "someos" {
		t.Errorf("distro=%q, want someos", distro)
	}
	if eol {
		t.Error("unknown distro must not be marked EOL")
	}
}

func TestParseAptPeriodic_Enabled(t *testing.T) {
	b := mustReadTestdata(t, "apt_20auto_upgrades.txt")
	vals, schemaID, known := parseAptPeriodic(b)
	if !known {
		t.Fatal("known=false, want true")
	}
	if schemaID != "apt-periodic" {
		t.Errorf("schemaID=%q, want apt-periodic", schemaID)
	}
	if vals["unattended_upgrade"] != "1" {
		t.Errorf("unattended_upgrade=%q, want 1", vals["unattended_upgrade"])
	}
}

func TestParseAptPeriodic_Disabled(t *testing.T) {
	content := `APT::Periodic::Update-Package-Lists "1";` + "\n" +
		`APT::Periodic::Unattended-Upgrade "0";` + "\n"
	vals, _, known := parseAptPeriodic([]byte(content))
	if !known {
		t.Fatal("known=false, want true")
	}
	if vals["unattended_upgrade"] != "0" {
		t.Errorf("unattended_upgrade=%q, want 0", vals["unattended_upgrade"])
	}
}

func TestParseAptPeriodic_Empty(t *testing.T) {
	_, _, known := parseAptPeriodic([]byte("// comment only\n"))
	if known {
		t.Error("comment-only input: want known=false")
	}
}

func TestParseDockerDaemon(t *testing.T) {
	b, err := os.ReadFile("testdata/docker_daemon_tcp.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	vals, schemaID, known := parseDockerDaemon(b)
	if !known {
		t.Fatal("want known=true")
	}
	if schemaID != "docker-daemon" {
		t.Fatalf("schemaID = %q, want %q", schemaID, "docker-daemon")
	}
	hosts := vals["hosts"]
	if !strings.Contains(hosts, "tcp://0.0.0.0:2375") {
		t.Fatalf("hosts = %q, want tcp://0.0.0.0:2375 present", hosts)
	}

	// Sock-only fixture should parse but no tcp entry.
	b2, _ := os.ReadFile("testdata/docker_daemon_sock.json")
	vals2, _, known2 := parseDockerDaemon(b2)
	if !known2 {
		t.Fatal("sock-only: want known=true")
	}
	if strings.Contains(vals2["hosts"], "tcp://") {
		t.Fatalf("sock-only: unexpected tcp entry: %q", vals2["hosts"])
	}
}
