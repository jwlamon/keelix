package collect

// Parser-fed tests for SVC052 (Syncthing) and SVC060 (Traefik).
// All ConfigFact construction routes through collectConfigInternal so the full
// parse→redact pipeline runs. Synthetic model.ConfigFact{Values: vals} literals
// that bypass redaction are forbidden per the FIX-10 discipline.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC052_ParserFed_NoAuth(t *testing.T) {
	c := findRegisteredCheck(t, "SVC052")

	t.Run("empty gui user fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "syncthing_noauth.xml"),
			parseSyncthingConfig,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseSyncthingConfig did not recognise noauth fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "syncthing-config" {
			t.Fatalf("SchemaID=%q, want syncthing-config", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC052" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC052: want failing finding for gui.auth=false; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("gui user set passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "syncthing_auth.xml"),
			parseSyncthingConfig,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseSyncthingConfig did not recognise auth fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC052" && f.IsFail() {
				t.Errorf("SVC052: must NOT fire for Syncthing GUI with user+password set; got %+v", f)
			}
		}
	})
}

func TestSVC052_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC052")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC052: want NotAssessed when Collector==nil, got %+v", findings)
	}
}

func TestSVC060_ParserFed_Insecure(t *testing.T) {
	c := findRegisteredCheck(t, "SVC060")

	t.Run("api.insecure=true fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "traefik_insecure.yml"),
			parseTraefikYml,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseTraefikYml did not recognise insecure fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "traefik-yml" {
			t.Fatalf("SchemaID=%q, want traefik-yml", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC060" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC060: want failing finding for api.insecure=true; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("api.insecure=false passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "traefik_secure.yml"),
			parseTraefikYml,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseTraefikYml did not recognise secure fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC060" && f.IsFail() {
				t.Errorf("SVC060: must NOT fire for api.insecure=false; got %+v", f)
			}
		}
	})
}

func TestSVC060_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC060")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC060: want NotAssessed when Collector==nil, got %+v", findings)
	}
}
