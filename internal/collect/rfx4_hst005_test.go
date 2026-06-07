package collect

// TestRFX4_HST005_ParserFed is the MANDATORY PARSER-FED regression test for
// RFX-4 / HST005. It guards against the dead-branch bug where the check keyed
// off a "fail2ban" ConfigFact SchemaID that no collector has ever emitted.
//
// The dead branch made the FileFact detection path unreachable: if a sysadmin
// had fail2ban installed (files present under /etc/fail2ban) but the process
// was temporarily stopped, HST005 would always fire even though protection was
// present — the only working path was the process check. The dead
// SchemaID=="fail2ban" loop on Configs could never pass, so the FileFact branch
// was effectively dead.
//
// Fix: remove the dead Configs loop; detect fail2ban presence via:
//   (a) a process Comm of "fail2ban-server" or "fail2ban" (Signals.Processes), OR
//   (b) a FileFact with Exists=true under /etc/fail2ban/ (Signals.Files, collected
//       by the allowlist-driven walker).
//
// Two tests are mandated by the spec meta-rule (real parser over committed fixture
// -> check Run()):
//
//  1. parseProcesses over testdata/ps_linux_fail2ban.txt -> fail2ban-server in
//     Processes -> HST005 must PASS (protection detected).
//
//  2. A ScanContext with no fail2ban process but a FileFact under /etc/fail2ban/
//     -> HST005 must PASS (file-based detection works).
//
//  3. A ScanContext with no fail2ban process, no fail2ban files, password auth on
//     -> HST005 must FIRE (Info finding, not Passed).

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

func TestRFX4_HST005_ParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "HST005")

	// sshdEffectivePassOn is a ConfigFact for sshd-effective with password auth on.
	// Built via the real parseSSHDConfig parser over an inline config (not synthetic).
	const sshdPassOn = "PasswordAuthentication yes\nPermitRootLogin prohibit-password\n"
	sshdVals, sshdSchema, sshdKnown := parseSSHDConfig([]byte(sshdPassOn))
	if !sshdKnown {
		t.Fatalf("parseSSHDConfig: known=false — inline fixture parse failed")
	}
	if sshdSchema != "sshd-effective" {
		t.Fatalf("parseSSHDConfig: schema=%q, want sshd-effective", sshdSchema)
	}
	sshdFact := model.ConfigFact{
		SchemaID:    sshdSchema,
		SchemaKnown: true,
		Source:      "<inline:PasswordAuthentication yes>",
		Values:      sshdVals,
	}

	t.Run("fail2ban-server process via parseProcesses fixture passes HST005", func(t *testing.T) {
		// Run the real parseProcesses parser over the committed fixture that
		// contains a fail2ban-server entry. Feed the resulting ProcessFacts into
		// HST005.Run() — this is the PARSER-FED path mandated by the spec.
		b := mustReadTestdata(t, filepath.Join("ps_linux_fail2ban.txt"))
		procs := parseProcesses(b)

		// Verify the parser produced a fail2ban-server ProcessFact (fixture sanity).
		var found bool
		for _, p := range procs {
			if p.Comm == "fail2ban-server" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("parseProcesses: fail2ban-server not found in fixture output; procs=%+v", procs)
		}

		ctx := &model.ScanContext{
			Collector: &model.Signals{
				Platform:  model.Platform{OS: "linux"},
				Configs:   []model.ConfigFact{sshdFact},
				Processes: procs,
			},
		}
		findings := c.Run(ctx)
		if len(findings) == 0 {
			t.Fatal("HST005: no findings returned")
		}
		if !findings[0].Passed {
			t.Fatalf("HST005: expected PASS when fail2ban-server process present (parsed from fixture); got %+v", findings[0])
		}
	})

	t.Run("fail2ban FileFact under /etc/fail2ban passes HST005", func(t *testing.T) {
		// The file-detection path: a FileFact with Exists=true under /etc/fail2ban/
		// must cause HST005 to pass even with no fail2ban process running.
		// This covers the case where fail2ban is installed but temporarily stopped.
		ctx := &model.ScanContext{
			Collector: &model.Signals{
				Platform: model.Platform{OS: "linux"},
				Configs:  []model.ConfigFact{sshdFact},
				// No fail2ban process — relies solely on the FileFact path.
				Processes: []model.ProcessFact{
					{Comm: "sshd", PID: 1402, UID: 0},
				},
				Files: []model.FileFact{
					// The walker collects /etc/fail2ban as a Prefix entry; this
					// represents a real file the walker would emit on a configured host.
					{Path: "/etc/fail2ban/jail.conf", Exists: true, Mode: "0644"},
				},
			},
		}
		findings := c.Run(ctx)
		if len(findings) == 0 {
			t.Fatal("HST005: no findings returned")
		}
		if !findings[0].Passed {
			t.Fatalf("RFX-4: HST005 must PASS when /etc/fail2ban/jail.conf FileFact is present; "+
				"got %+v — dead-branch bug: the file detection path is not working", findings[0])
		}
	})

	t.Run("no fail2ban process, no fail2ban files, password auth on fires HST005", func(t *testing.T) {
		// Neither a fail2ban process nor a /etc/fail2ban FileFact — HST005 must fire.
		ctx := &model.ScanContext{
			Collector: &model.Signals{
				Platform: model.Platform{OS: "linux"},
				Configs:  []model.ConfigFact{sshdFact},
				Processes: []model.ProcessFact{
					{Comm: "sshd", PID: 1402, UID: 0},
				},
				Files: []model.FileFact{
					// /etc/fail2ban/ directory entry absent (exists=false simulates no install).
					{Path: "/etc/fail2ban/jail.conf", Exists: false},
				},
			},
		}
		findings := c.Run(ctx)
		if len(findings) == 0 {
			t.Fatal("HST005: no findings returned")
		}
		if findings[0].Passed {
			t.Fatalf("HST005: expected FAIL when no fail2ban present with password auth on; got pass: %+v", findings[0])
		}
	})
}
