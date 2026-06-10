package collect

// TestRFX5_HST_PipelineIntegration is the MANDATORY PARSER-FED pipeline
// integration test that locks the entire host-OS posture check class.
//
// This is the regression that would have caught every bug found in this
// remediation sprint. It drives the REAL parse->check path — NOT synthetic
// ConfigFacts with hand-written keys — so any future parser↔check key-name
// mismatch will fail here immediately.
//
// Scenario: a realistic temp /etc-shaped fixture set is written:
//
//   - sshd -T-style effective output (passwordauthentication=yes,
//     permitrootlogin=yes, port 22) with a non-loopback socket on :22
//   - /etc/passwd with two UID-0 accounts (root + toor)
//   - /etc/shadow with one empty-password account (alice)
//   - /etc/sudoers with a NOPASSWD directive
//   - /etc/apt/apt.conf.d/20auto-upgrades with Unattended-Upgrade "1"
//   - /etc/os-release for a non-EOL Debian 12 host
//
// The real collect parsers are called via collectConfigInternal on each temp
// file to produce model.ConfigFact values. These are assembled into a single
// model.Signals that is fed to the registered HST checks. Expected outcomes:
//
//   - HST020 FIRES  — NOPASSWD rule detected in sudoers
//   - HST021 FIRES  — multiple UID-0 accounts detected in passwd
//   - HST022 FIRES  — empty-password account detected in shadow
//   - HST013 PASSES — unattended-upgrade is enabled (must NOT fire red)
//   - HST003 FIRES Fatal — effective source + non-loopback socket + password+root

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/host"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX5_HST_PipelineIntegration(t *testing.T) {
	tmp := t.TempDir()

	// --- write fixture files ---

	// sshd effective output (sshd -T style): passwordauthentication=yes,
	// permitrootlogin=yes, non-loopback listen, port 22.
	sshdEffectiveContent := `port 22
addressfamily any
listenaddress 0.0.0.0
listenaddress ::
permitrootlogin yes
pubkeyauthentication yes
passwordauthentication yes
permitemptypasswords no
kbdinteractiveauthentication no
usepam yes
x11forwarding yes
maxauthtries 6
logingracetime 120
allowusers
allowgroups
`
	sshdEffPath := filepath.Join(tmp, "sshd_effective.txt")
	if err := os.WriteFile(sshdEffPath, []byte(sshdEffectiveContent), 0o644); err != nil {
		t.Fatalf("write sshd_effective: %v", err)
	}

	// /etc/passwd: root + toor both have UID 0 (duplicate UID-0), alice is normal.
	passwdContent := "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"toor:x:0:0:toor:/root:/bin/bash\n" +
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
	passwdPath := filepath.Join(tmp, "passwd")
	if err := os.WriteFile(passwdPath, []byte(passwdContent), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	// /etc/shadow: alice has empty password field; bob has "!" (locked).
	shadowContent := "root:$6$xyz$longhashhere:19000:0:99999:7:::\n" +
		"daemon:*:19000:0:99999:7:::\n" +
		"alice::19000:0:99999:7:::\n" +
		"bob:!:19000:0:99999:7:::\n"
	shadowPath := filepath.Join(tmp, "shadow")
	if err := os.WriteFile(shadowPath, []byte(shadowContent), 0o644); err != nil {
		t.Fatalf("write shadow: %v", err)
	}

	// /etc/sudoers: contains a NOPASSWD directive for deploy.
	sudoersContent := "# /etc/sudoers\n" +
		"root    ALL=(ALL:ALL) ALL\n" +
		"%sudo   ALL=(ALL:ALL) ALL\n" +
		"deploy  ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp\n"
	sudoersPath := filepath.Join(tmp, "sudoers")
	if err := os.WriteFile(sudoersPath, []byte(sudoersContent), 0o644); err != nil {
		t.Fatalf("write sudoers: %v", err)
	}

	// /etc/apt/apt.conf.d/20auto-upgrades: both keys enabled.
	aptContent := "APT::Periodic::Update-Package-Lists \"1\";\n" +
		"APT::Periodic::Unattended-Upgrade \"1\";\n"
	aptPath := filepath.Join(tmp, "20auto-upgrades")
	if err := os.WriteFile(aptPath, []byte(aptContent), 0o644); err != nil {
		t.Fatalf("write apt: %v", err)
	}

	// /etc/os-release: Debian 12 (not EOL in 2026).
	osReleaseContent := "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n" +
		"NAME=\"Debian GNU/Linux\"\n" +
		"VERSION_ID=\"12\"\n" +
		"VERSION=\"12 (bookworm)\"\n" +
		"ID=debian\n" +
		"VERSION_CODENAME=bookworm\n"
	_ = osReleaseContent // used below for Platform setup

	// --- run real parsers via collectConfigInternal ---

	// NOTE: sshd config values are boolean/numeric state ("yes"/"no"/numbers),
	// NOT credentials. collectConfigInternal runs redactConfigValues which
	// matches "password" in "passwordauthentication" and corrupts it to "[secret]".
	// This is the same reason collectSSHStatic explicitly skips redactConfigValues
	// (see collect_ssh_linux.go). We call the parser directly and build the fact
	// manually — the same pattern used in rfx3_hst003_test.go.
	sshdBytes, err := os.ReadFile(sshdEffPath)
	if err != nil {
		t.Fatalf("read sshd_effective: %v", err)
	}
	sshdVals, sshdSchemaID, sshdKnown := parseSSHDashT(sshdBytes)
	if !sshdKnown {
		t.Fatalf("parseSSHDashT: known=false on fixture")
	}
	if sshdSchemaID != "sshd-effective" {
		t.Fatalf("parseSSHDashT: schemaID=%q, want sshd-effective", sshdSchemaID)
	}
	if sshdVals["_source"] != "effective" {
		t.Fatalf("parseSSHDashT: _source=%q, want effective — Fatal gate will be unreachable",
			sshdVals["_source"])
	}
	sshdFact := model.ConfigFact{
		Source:      sshdEffPath,
		SchemaID:    sshdSchemaID,
		SchemaKnown: true,
		Values:      sshdVals,
	}

	passwdFact := collectConfigInternal(passwdPath, parsePasswd)
	if !passwdFact.SchemaKnown {
		t.Fatalf("parsePasswd: SchemaKnown=false on fixture; Values=%v", passwdFact.Values)
	}
	if passwdFact.SchemaID != "accounts-passwd" {
		t.Fatalf("parsePasswd: SchemaID=%q, want accounts-passwd", passwdFact.SchemaID)
	}

	shadowFact := collectConfigInternal(shadowPath, parseShadow)
	if !shadowFact.SchemaKnown {
		t.Fatalf("parseShadow: SchemaKnown=false on fixture; Values=%v", shadowFact.Values)
	}
	if shadowFact.SchemaID != "accounts-shadow" {
		t.Fatalf("parseShadow: SchemaID=%q, want accounts-shadow", shadowFact.SchemaID)
	}

	sudoersFact := collectConfigInternal(sudoersPath, parseSudoers)
	if !sudoersFact.SchemaKnown {
		t.Fatalf("parseSudoers: SchemaKnown=false on fixture; Values=%v", sudoersFact.Values)
	}
	if sudoersFact.SchemaID != "accounts-sudoers" {
		t.Fatalf("parseSudoers: SchemaID=%q, want accounts-sudoers", sudoersFact.SchemaID)
	}

	aptFact := collectConfigInternal(aptPath, parseAptPeriodic)
	if !aptFact.SchemaKnown {
		t.Fatalf("parseAptPeriodic: SchemaKnown=false on fixture; Values=%v", aptFact.Values)
	}
	if aptFact.SchemaID != "apt-periodic" {
		t.Fatalf("parseAptPeriodic: SchemaID=%q, want apt-periodic", aptFact.SchemaID)
	}

	// --- assemble model.Signals with all parser-produced facts ---
	// Platform is linux so HST013 does not skip. Sockets include a non-loopback
	// listener on :22 so HST003 can reach the Fatal branch.
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux", Distro: "debian", Version: "12"},
		Configs: []model.ConfigFact{
			sshdFact,
			passwdFact,
			shadowFact,
			sudoersFact,
			aptFact,
		},
		Sockets: []model.ListeningSocket{
			{Proto: "tcp", Bind: "0.0.0.0", Port: 22},
		},
	}

	ctx := &model.ScanContext{Collector: sigs}

	// --- assert HST020 FIRES (NOPASSWD in sudoers) ---
	t.Run("HST020_fires_nopasswd", func(t *testing.T) {
		c := findRegisteredCheck(t, "HST020")
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "HST020" && f.IsFail() {
				return // correct
			}
		}
		t.Fatalf("HST020 must fire for NOPASSWD in sudoers; got %+v\nValues: %v",
			findings, sudoersFact.Values)
	})

	// --- assert HST021 FIRES (duplicate UID-0 in passwd) ---
	t.Run("HST021_fires_duplicate_uid0", func(t *testing.T) {
		c := findRegisteredCheck(t, "HST021")
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "HST021" && f.IsFail() {
				return // correct
			}
		}
		t.Fatalf("HST021 must fire for duplicate UID-0 in passwd; got %+v\nValues: %v",
			findings, passwdFact.Values)
	})

	// --- assert HST022 FIRES (empty-password account in shadow) ---
	t.Run("HST022_fires_empty_password", func(t *testing.T) {
		c := findRegisteredCheck(t, "HST022")
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "HST022" && f.IsFail() {
				return // correct
			}
		}
		t.Fatalf("HST022 must fire for empty-password account in shadow; got %+v\nValues: %v",
			findings, shadowFact.Values)
	})

	// --- assert HST013 PASSES (unattended-upgrade enabled) ---
	t.Run("HST013_passes_upgrades_enabled", func(t *testing.T) {
		c := findRegisteredCheck(t, "HST013")
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.Passed {
				return // correct: at least one passing finding
			}
		}
		t.Fatalf("HST013 fired RED on a host with Unattended-Upgrade=1 — key mismatch regression\n"+
			"findings: %+v\nValues: %v", findings, aptFact.Values)
	})

	// --- assert HST003 fires Fatal (effective source + non-loopback + password+root) ---
	t.Run("HST003_fires_fatal_effective_exposed", func(t *testing.T) {
		c := findRegisteredCheck(t, "HST003")
		findings := c.Run(ctx)
		if len(findings) == 0 {
			t.Fatal("HST003: no findings returned")
		}
		f := findings[0]
		if f.Passed {
			t.Fatalf("HST003: expected failing finding; passwordauthentication=yes + permitrootlogin=yes + 0.0.0.0:22 should fire")
		}
		if !f.Fatal {
			t.Fatalf("HST003: Fatal=false — effective-source fatal gate is still dead\n"+
				"finding: %+v\nValues: %v", f, sshdFact.Values)
		}
	})
}
