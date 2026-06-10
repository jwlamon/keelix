package collect

// Parser-fed tests for SVC030 (Vaultwarden admin token).
// The SLICE-D parser emits ONLY derived non-secret signals:
//
//	admin_token.present, admin_token.is_argon2, admin_token.length_band
//
// The raw token value MUST NOT appear in Values; this test also asserts that.
// All ConfigFact construction routes through collectConfigInternal so the full
// parse→redact pipeline runs. Synthetic model.ConfigFact{Values: vals} literals
// that bypass redaction are forbidden per the FIX-10 discipline.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC030_ParserFed_Absent(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")

	fact := collectConfigInternal(
		filepath.Join("testdata", "vaultwarden_absent.env"),
		parseVaultwardenEnv,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseVaultwardenEnv did not recognise absent fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "vaultwarden-env" {
		t.Fatalf("SchemaID=%q, want vaultwarden-env", fact.SchemaID)
	}
	// Safety: raw token must never appear in Values.
	if _, rawPresent := fact.Values["ADMIN_TOKEN"]; rawPresent {
		t.Fatal("parseVaultwardenEnv: raw ADMIN_TOKEN must not appear in Values (derived signals only)")
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC030" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC030: want failing finding for absent admin token; got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC030_ParserFed_Weak(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")

	fact := collectConfigInternal(
		filepath.Join("testdata", "vaultwarden_weak.env"),
		parseVaultwardenEnv,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseVaultwardenEnv did not recognise weak fixture; values: %v", fact.Values)
	}
	if _, rawPresent := fact.Values["ADMIN_TOKEN"]; rawPresent {
		t.Fatal("parseVaultwardenEnv: raw ADMIN_TOKEN must not appear in Values")
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC030" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC030: want failing finding for weak non-argon2 token; got %+v\nValues: %v", findings, fact.Values)
}

// TestSVC030_ParserFed_Argon2 verifies that a Vaultwarden env file with a
// properly Argon2-hashed ADMIN_TOKEN yields a passing finding (not a false
// positive). The parser emits derived signals only; the raw token is not stored.
func TestSVC030_ParserFed_Argon2(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")

	fact := collectConfigInternal(
		filepath.Join("testdata", "vaultwarden_argon2.env"),
		parseVaultwardenEnv,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseVaultwardenEnv did not recognise argon2 fixture; values: %v", fact.Values)
	}
	if _, rawPresent := fact.Values["ADMIN_TOKEN"]; rawPresent {
		t.Fatal("parseVaultwardenEnv: raw ADMIN_TOKEN must not appear in Values (derived signals only)")
	}
	// The argon2 fixture must parse as present + argon2.
	if got := fact.Values["admin_token.present"]; got != "true" {
		t.Errorf("admin_token.present=%q, want true", got)
	}
	if got := fact.Values["admin_token.is_argon2"]; got != "true" {
		t.Errorf("admin_token.is_argon2=%q, want true", got)
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC030" && f.IsFail() {
			t.Errorf("SVC030: must NOT fire for Argon2-hashed admin token; got %+v", f)
		}
	}
}

func TestSVC030_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC030: want NotAssessed when Collector==nil, got %+v", findings)
	}
}

// R2-4: SVC030 must also fire when Vaultwarden uses config.json (admin-panel default).
// Previously the vaultwarden-env kindSpec listed config.json as an expected
// basename but parseVaultwardenEnv is a KEY=VALUE parser → SchemaKnown=false →
// SVC030 silently returns NotAssessed for the common config.json deployment.

func TestSVC030_JSON_ParserFed_Absent(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")

	fact := collectConfigInternal(
		filepath.Join("testdata", "vaultwarden_absent.json"),
		parseVaultwardenJSON,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseVaultwardenJSON did not recognise absent fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "vaultwarden-json" {
		t.Fatalf("SchemaID=%q, want vaultwarden-json", fact.SchemaID)
	}
	if _, rawPresent := fact.Values["admin_token"]; rawPresent {
		t.Fatal("parseVaultwardenJSON: raw admin_token must not appear in Values (derived signals only)")
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC030" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC030: want failing finding for absent admin token in config.json; got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC030_JSON_ParserFed_Weak(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")

	fact := collectConfigInternal(
		filepath.Join("testdata", "vaultwarden_weak.json"),
		parseVaultwardenJSON,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseVaultwardenJSON did not recognise weak fixture; values: %v", fact.Values)
	}
	if _, rawPresent := fact.Values["admin_token"]; rawPresent {
		t.Fatal("parseVaultwardenJSON: raw admin_token must not appear in Values")
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC030" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC030: want failing finding for weak non-argon2 token in config.json; got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC030_JSON_ParserFed_Argon2(t *testing.T) {
	c := findRegisteredCheck(t, "SVC030")

	fact := collectConfigInternal(
		filepath.Join("testdata", "vaultwarden_argon2.json"),
		parseVaultwardenJSON,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseVaultwardenJSON did not recognise argon2 fixture; values: %v", fact.Values)
	}
	if _, rawPresent := fact.Values["admin_token"]; rawPresent {
		t.Fatal("parseVaultwardenJSON: raw admin_token must not appear in Values (derived signals only)")
	}
	if got := fact.Values["admin_token.present"]; got != "true" {
		t.Errorf("admin_token.present=%q, want true", got)
	}
	if got := fact.Values["admin_token.is_argon2"]; got != "true" {
		t.Errorf("admin_token.is_argon2=%q, want true", got)
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC030" && f.IsFail() {
			t.Errorf("SVC030: must NOT fire for Argon2-hashed admin token in config.json; got %+v", f)
		}
	}
}

// TestSVC030_JSON_KindTableSplit verifies that discover.go has a separate
// vaultwarden-json kindSpec (not bundled into vaultwarden-env).
func TestSVC030_JSON_KindTableSplit(t *testing.T) {
	// vaultwarden-env must NOT list config.json as an expected basename
	for i := range kindTable {
		spec := &kindTable[i]
		if spec.schemaID != "vaultwarden-env" {
			continue
		}
		for _, b := range spec.expectedBasenames {
			if b == "config.json" {
				t.Error("vaultwarden-env kindSpec must NOT include config.json (it is a JSON file, not dotenv)")
			}
		}
	}
	// vaultwarden-json must exist and accept config.json
	found := false
	for i := range kindTable {
		spec := &kindTable[i]
		if spec.schemaID != "vaultwarden-json" {
			continue
		}
		found = true
		hasJSON := false
		for _, b := range spec.expectedBasenames {
			if b == "config.json" {
				hasJSON = true
			}
		}
		if !hasJSON {
			t.Error("vaultwarden-json kindSpec must include config.json in expectedBasenames")
		}
	}
	if !found {
		t.Error("kindTable must have a vaultwarden-json kindSpec")
	}
}
