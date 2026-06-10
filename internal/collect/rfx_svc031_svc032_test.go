package collect

// Parser-fed tests for SVC031 (Gitea) and SVC032 (Jenkins).
// All ConfigFact construction routes through collectConfigInternal so the full
// parse→redact pipeline runs. Synthetic model.ConfigFact{Values: vals} literals
// that bypass redaction are forbidden per the FIX-10 discipline.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC031_ParserFed_InstallUnlocked(t *testing.T) {
	c := findRegisteredCheck(t, "SVC031")

	t.Run("INSTALL_LOCK=false fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "gitea_unlocked.ini"),
			parseGiteaIni,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseGiteaIni did not recognise unlocked fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "gitea-ini" {
			t.Fatalf("SchemaID=%q, want gitea-ini", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC031" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC031: want failing finding for INSTALL_LOCK=false; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("INSTALL_LOCK=true passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "gitea_locked.ini"),
			parseGiteaIni,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseGiteaIni did not recognise locked fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC031" && f.IsFail() {
				t.Errorf("SVC031: must NOT fire for INSTALL_LOCK=true; got %+v", f)
			}
		}
	})
}

func TestSVC031_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC031")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC031: want NotAssessed when Collector==nil, got %+v", findings)
	}
}

// TestSVC031_ParserFed_AbsentInstallLock verifies that a fully configured
// gitea app.ini that omits INSTALL_LOCK yields NotAssessed (not a spurious
// FAIL). Bug (c): absent key defaulted to "false" → SVC031 fired erroneously.
func TestSVC031_ParserFed_AbsentInstallLock(t *testing.T) {
	c := findRegisteredCheck(t, "SVC031")

	fact := collectConfigInternal(
		filepath.Join("testdata", "gitea_db_only.ini"),
		parseGiteaIni,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseGiteaIni did not recognise db-only fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "gitea-ini" {
		t.Fatalf("SchemaID=%q, want gitea-ini", fact.SchemaID)
	}
	// When INSTALL_LOCK is absent, the parser must NOT emit "false" — it must
	// emit the sentinel so SVC031 returns NotAssessed.
	if fact.Values["INSTALL_LOCK"] == "false" {
		t.Errorf("parseGiteaIni: INSTALL_LOCK=%q on absent-key fixture; want absent/empty (not spurious false)", fact.Values["INSTALL_LOCK"])
	}

	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC031" && f.Status == model.StatusNotAssessed {
			return
		}
	}
	t.Fatalf("SVC031: want NotAssessed for absent INSTALL_LOCK (DB-configured gitea); got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC032_ParserFed_SecurityDisabled(t *testing.T) {
	c := findRegisteredCheck(t, "SVC032")

	t.Run("useSecurity=false fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "jenkins_nosecurity.xml"),
			parseJenkinsConfig,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseJenkinsConfig did not recognise nosecurity fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "jenkins-config" {
			t.Fatalf("SchemaID=%q, want jenkins-config", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC032" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC032: want failing finding for useSecurity=false; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("useSecurity=true passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "jenkins_security.xml"),
			parseJenkinsConfig,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseJenkinsConfig did not recognise security fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC032" && f.IsFail() {
				t.Errorf("SVC032: must NOT fire for useSecurity=true; got %+v", f)
			}
		}
	})
}

func TestSVC032_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC032")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC032: want NotAssessed when Collector==nil, got %+v", findings)
	}
}
