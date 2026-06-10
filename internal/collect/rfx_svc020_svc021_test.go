package collect

// Parser-fed tests for SVC020 (Grafana) and SVC021 (Prometheus).
// All ConfigFact construction routes through collectConfigInternal so the full
// parse→redact pipeline runs. Synthetic model.ConfigFact{Values: vals} literals
// that bypass redaction are forbidden per the FIX-10 discipline.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC020_ParserFed_AnonEnabled(t *testing.T) {
	c := findRegisteredCheck(t, "SVC020")

	t.Run("anonymous access enabled fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "grafana_anon.ini"),
			parseGrafanaIni,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseGrafanaIni did not recognise anon fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "grafana-ini" {
			t.Fatalf("SchemaID=%q, want grafana-ini", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC020" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC020: want failing finding for anon enabled; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("secure grafana passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "grafana_secure.ini"),
			parseGrafanaIni,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseGrafanaIni did not recognise secure fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC020" && f.IsFail() {
				t.Errorf("SVC020: must NOT fire for disabled anon access + non-default admin creds; got %+v", f)
			}
		}
	})
}

func TestSVC020_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC020")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC020: want NotAssessed when Collector==nil, got %+v", findings)
	}
}

// TestSVC020_ParserFed_GrafanaAbsentAdminCreds verifies that a grafana.ini
// without any [security] section (absent admin_user/admin_password) is treated
// as default admin credentials (admin/admin) and SVC020 fires.
// Bug (d): absent keys were treated as non-default → false Pass.
func TestSVC020_ParserFed_GrafanaAbsentAdminCreds(t *testing.T) {
	c := findRegisteredCheck(t, "SVC020")

	fact := collectConfigInternal(
		filepath.Join("testdata", "grafana_nodefaults.ini"),
		parseGrafanaIni,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseGrafanaIni did not recognise no-defaults fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "grafana-ini" {
		t.Fatalf("SchemaID=%q, want grafana-ini", fact.SchemaID)
	}
	// Bug (d): absent admin creds must yield admin.default="true".
	if got := fact.Values["admin.default"]; got != "true" {
		t.Errorf("parseGrafanaIni: admin.default=%q on absent-creds fixture; want true (built-in default is admin/admin)", got)
	}

	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC020" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC020: want failing finding for absent admin creds (built-in default admin/admin); got %+v\nValues: %v", findings, fact.Values)
}

// TestSVC020_ParserFed_RenamedUserDefaultPass verifies that a grafana.ini where
// admin_user is renamed but admin_password is still "admin" fires SVC020.
// R3-2 fix: admin.default must be "true" (unsafe) when EITHER user OR password
// equals "admin"; previously OR→AND logic treated this case as safe.
func TestSVC020_ParserFed_RenamedUserDefaultPass(t *testing.T) {
	c := findRegisteredCheck(t, "SVC020")

	fact := collectConfigInternal(
		filepath.Join("testdata", "grafana_renamed_user_default_pass.ini"),
		parseGrafanaIni,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseGrafanaIni did not recognise renamed-user fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "grafana-ini" {
		t.Fatalf("SchemaID=%q, want grafana-ini", fact.SchemaID)
	}
	// admin_user="ops" (non-default) but admin_password="admin" (default).
	// The OR→AND fix: admin.default must be "true" because password is still default.
	if got := fact.Values["admin.default"]; got != "true" {
		t.Errorf("parseGrafanaIni: admin.default=%q for renamed-user/default-pass; want true (password is still default admin)", got)
	}

	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC020" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC020: want failing finding for renamed user + default password (admin); got %+v\nValues: %v", findings, fact.Values)
}

// TestSVC021_ParserFed_StdPrometheusYml asserts that a standard prometheus.yml
// (scrape-side config only, no web.yml API auth) yields NotAssessed — not a
// false FAIL. prometheus.yml only holds outbound scrape auth; inbound API auth
// lives in the separate web.yml (--web.config.file). SVC021 cannot determine
// API auth from prometheus.yml alone, so it must return NotAssessed.
//
// This test routes the fixture through collectConfigInternal so that the full
// parse→redact pipeline runs (discipline: no synthetic ConfigFact literals).
func TestSVC021_ParserFed_StdPrometheusYml(t *testing.T) {
	c := findRegisteredCheck(t, "SVC021")

	fixturePath := filepath.Join("testdata", "prometheus_noauth.yml")
	fact := collectConfigInternal(fixturePath, parsePrometheusYml)
	if !fact.SchemaKnown {
		t.Fatalf("collectConfigInternal: SchemaKnown=false for prometheus_noauth.yml — fixture parse failed\nValues: %v", fact.Values)
	}
	if fact.SchemaID != "prometheus-yml" {
		t.Fatalf("collectConfigInternal: SchemaID=%q, want prometheus-yml", fact.SchemaID)
	}
	// The parser must set auth.determinable="false" (prometheus.yml has no API auth info).
	if got := fact.Values["auth.determinable"]; got != "false" {
		t.Errorf("parsePrometheusYml: auth.determinable=%q, want false (prometheus.yml cannot determine API auth)", got)
	}

	ctx := &model.ScanContext{
		Collector: &model.Signals{Configs: []model.ConfigFact{fact}},
	}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC021" && f.Status == model.StatusNotAssessed {
			return
		}
	}
	t.Fatalf("SVC021: want NotAssessed for standard prometheus.yml (API auth is in web.yml, not visible here); got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC021_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC021")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC021: want NotAssessed when Collector==nil, got %+v", findings)
	}
}
