package collect

// TestRFX3_HST003_ParserFed contains the MANDATORY PARSER-FED regression tests
// for RFX-3. Two linked bugs were masked by synthetic unit tests that
// pre-populated model.Signals with hand-written keys/values:
//
// (a) Fatal cap dead — collectSSHEffective / parseSSHDashT never set
//
//	Values["_source"], leaving it "" instead of "effective". The Fatal gate
//	in hst003.go checks `source == "effective"`, so on real `sshd -T` output
//	the Fatal RED finding was unreachable; only the Medium non-Fatal branch
//	ever fired. Fix: parseSSHDashT now sets _source="effective".
//
// (b) Case-insensitive value comparisons — parseSSHDConfig lowercases the
//
//	KEY but not the VALUE. A real sshd_config with "PasswordAuthentication
//	Yes" / "PermitRootLogin Yes" (capital-V) caused HST001/002/003/004/005
//	to silently PASS. Fix: value comparisons in HST001-005 now use
//	strings.EqualFold.
//
// These tests run the real parsers over committed /etc fixtures and feed the
// produced ConfigFact into the actual check Run() — the only test form that
// can catch parser↔check contract bugs.

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

// TestRFX3_HST003_EffectiveSource_Fatal verifies the end-to-end pipeline:
//
//	parseSSHDashT (real parser) over testdata/sshd_effective.txt
//	  -> ConfigFact with _source="effective"
//	  -> HST003.Run() with non-loopback socket
//	  -> Fatal=true
//
// Before the fix, parseSSHDashT did not set _source, so _source=="" and the
// Fatal gate was never reached; the finding fired non-Fatal/Medium instead.
func TestRFX3_HST003_EffectiveSource_Fatal(t *testing.T) {
	c := findRegisteredCheck(t, "HST003")

	b := mustReadTestdata(t, "sshd_effective.txt")
	vals, schemaID, known := parseSSHDashT(b)
	if !known {
		t.Fatalf("parseSSHDashT: known=false on sshd_effective.txt fixture")
	}
	if schemaID != "sshd-effective" {
		t.Fatalf("parseSSHDashT: schemaID=%q, want sshd-effective", schemaID)
	}

	// Verify the parser now sets _source=effective (the fix).
	if vals["_source"] != "effective" {
		t.Fatalf("parseSSHDashT: _source=%q, want effective — Fatal gate will be unreachable",
			vals["_source"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sshd_effective.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
			// sshd_effective.txt has listenaddress 0.0.0.0, port 22.
			Sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "0.0.0.0", Port: 22},
			},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("HST003: no findings returned")
	}
	f := findings[0]
	if f.Passed {
		t.Fatalf("HST003: expected failing finding, got pass — passwordauthentication+permitrootlogin=yes with 0.0.0.0 should fire")
	}
	if !f.Fatal {
		t.Fatalf("HST003: Fatal=false — effective source fatal gate is still dead\n"+
			"finding: %+v\nValues: %v", f, vals)
	}
}

// TestRFX3_HST003_StaticSource_NonFatal verifies that the static path (sshd_config)
// STILL does not set Fatal — this is the intended behaviour that must be preserved.
func TestRFX3_HST003_StaticSource_NonFatal(t *testing.T) {
	c := findRegisteredCheck(t, "HST003")

	// Use the caps fixture: "PasswordAuthentication Yes" / "PermitRootLogin Yes"
	b := mustReadTestdata(t, "sshd_config_caps.txt")
	vals, schemaID, known := parseSSHDConfig(b)
	if !known {
		t.Fatalf("parseSSHDConfig: known=false on sshd_config_caps.txt fixture")
	}
	if schemaID != "sshd-effective" {
		t.Fatalf("parseSSHDConfig: schemaID=%q, want sshd-effective", schemaID)
	}

	// Static parser sets _source=static.
	if vals["_source"] != "static" {
		t.Fatalf("parseSSHDConfig: _source=%q, want static", vals["_source"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sshd_config_caps.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
			Sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "0.0.0.0", Port: 22},
			},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("HST003: no findings returned")
	}
	f := findings[0]
	if f.Passed {
		t.Fatalf("HST003: expected failing finding for static path with Yes values, got pass")
	}
	if f.Fatal {
		t.Fatalf("HST003: Fatal=true on static source — fatal gate must not engage for static path")
	}
	if f.Confidence != model.ConfidenceMedium {
		t.Fatalf("HST003: static path should produce ConfidenceMedium, got %v", f.Confidence)
	}
}

// TestRFX3_HST001_CapsValue_Fires verifies that parseSSHDConfig over a fixture
// with "PasswordAuthentication Yes" (capital V) feeds a ConfigFact that causes
// HST001 to FIRE. Before the fix, the lowercase comparison "yes" != "Yes" caused
// HST001 to silently pass.
func TestRFX3_HST001_CapsValue_Fires(t *testing.T) {
	c := findRegisteredCheck(t, "HST001")

	b := mustReadTestdata(t, "sshd_config_caps.txt")
	vals, schemaID, known := parseSSHDConfig(b)
	if !known {
		t.Fatalf("parseSSHDConfig: known=false on sshd_config_caps.txt fixture")
	}

	// Verify the parser preserved the original case of the value (not blanket-lowercased).
	if vals["passwordauthentication"] != "Yes" {
		t.Fatalf("parseSSHDConfig: passwordauthentication=%q, want Yes — parser must NOT blanket-lowercase values",
			vals["passwordauthentication"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sshd_config_caps.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("HST001: no findings returned")
	}
	if findings[0].Passed {
		t.Fatalf("HST001: silently passed on PasswordAuthentication=Yes — case-insensitive comparison regression\n"+
			"Values: %v", vals)
	}
}

// TestRFX3_HST002_CapsValue_Fires verifies that HST002 fires when the static
// config contains "PermitRootLogin Yes" (capital V).
func TestRFX3_HST002_CapsValue_Fires(t *testing.T) {
	c := findRegisteredCheck(t, "HST002")

	b := mustReadTestdata(t, "sshd_config_caps.txt")
	vals, schemaID, known := parseSSHDConfig(b)
	if !known {
		t.Fatalf("parseSSHDConfig: known=false on sshd_config_caps.txt fixture")
	}

	// Verify the parser preserved the original case of the value.
	if vals["permitrootlogin"] != "Yes" {
		t.Fatalf("parseSSHDConfig: permitrootlogin=%q, want Yes — parser must NOT blanket-lowercase values",
			vals["permitrootlogin"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sshd_config_caps.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("HST002: no findings returned")
	}
	if findings[0].Passed {
		t.Fatalf("HST002: silently passed on PermitRootLogin=Yes — case-insensitive comparison regression\n"+
			"Values: %v", vals)
	}
}

// TestRFX3_HST004_CapsValue_Fires is the MANDATORY PARSER-FED regression test
// for the HST004 EqualFold fix. It runs parseSSHDConfig over the committed
// sshd_config_caps.txt fixture (which has 'X11Forwarding Yes' and
// 'PermitEmptyPasswords Yes' — capital-V values) and confirms that HST004 fires.
//
// Before the fix, strings comparison "yes" != "Yes" caused both x11forwarding
// and permitemptypasswords sub-checks to silently pass.
func TestRFX3_HST004_CapsValue_Fires(t *testing.T) {
	c := findRegisteredCheck(t, "HST004")

	b := mustReadTestdata(t, "sshd_config_caps.txt")
	vals, schemaID, known := parseSSHDConfig(b)
	if !known {
		t.Fatalf("parseSSHDConfig: known=false on sshd_config_caps.txt fixture")
	}

	// The fixture must have capital-V values for both keys (verify the fixture is correct).
	if vals["x11forwarding"] != "Yes" {
		t.Fatalf("parseSSHDConfig: x11forwarding=%q, want Yes — fixture sshd_config_caps.txt must have 'X11Forwarding Yes'",
			vals["x11forwarding"])
	}
	if vals["permitemptypasswords"] != "Yes" {
		t.Fatalf("parseSSHDConfig: permitemptypasswords=%q, want Yes — fixture sshd_config_caps.txt must have 'PermitEmptyPasswords Yes'",
			vals["permitemptypasswords"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sshd_config_caps.txt"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("HST004: no findings returned")
	}
	if findings[0].Passed {
		t.Fatalf("HST004: silently passed on X11Forwarding=Yes / PermitEmptyPasswords=Yes — EqualFold regression\n"+
			"Values: %v", vals)
	}
}

// TestRFX3_HST005_CapsValue_Fires is the MANDATORY PARSER-FED regression test
// for the HST005 EqualFold fix. It runs parseSSHDConfig over the committed
// sshd_config_caps.txt fixture (which has 'PasswordAuthentication Yes' —
// capital-V) and confirms that HST005 fires (no fail2ban present).
//
// Before the fix, the passPresent && !strings.EqualFold comparison treated
// "Yes" as not-"yes" (falsy), so the early-return PASS branch was taken and
// HST005 never reached the brute-force check.
func TestRFX3_HST005_CapsValue_Fires(t *testing.T) {
	c := findRegisteredCheck(t, "HST005")

	b := mustReadTestdata(t, "sshd_config_caps.txt")
	vals, schemaID, known := parseSSHDConfig(b)
	if !known {
		t.Fatalf("parseSSHDConfig: known=false on sshd_config_caps.txt fixture")
	}

	// The fixture must have capital-V PasswordAuthentication.
	if vals["passwordauthentication"] != "Yes" {
		t.Fatalf("parseSSHDConfig: passwordauthentication=%q, want Yes — fixture must have 'PasswordAuthentication Yes'",
			vals["passwordauthentication"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "sshd_config_caps.txt"),
		Values:      vals,
	}
	// No fail2ban process, no fail2ban config — HST005 must fire.
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform:  model.Platform{OS: "linux"},
			Configs:   []model.ConfigFact{fact},
			Processes: []model.ProcessFact{},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("HST005: no findings returned")
	}
	if findings[0].Passed {
		t.Fatalf("HST005: silently passed on PasswordAuthentication=Yes with no fail2ban — EqualFold regression\n"+
			"Values: %v", vals)
	}
}
