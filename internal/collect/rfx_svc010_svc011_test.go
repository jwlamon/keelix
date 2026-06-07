package collect

// Parser-fed tests for SVC010 (*arr) and SVC011 (qBittorrent).
// These run the REAL SLICE-D parsers over committed testdata fixtures and feed
// the produced ConfigFact to the check via collectConfigInternal so that the
// full parse→redact pipeline runs. Synthetic model.ConfigFact{Values: vals}
// literals that bypass redaction are forbidden per the FIX-10 discipline.

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

func TestSVC010_ParserFed_ArrNoAuth(t *testing.T) {
	c := findRegisteredCheck(t, "SVC010")

	t.Run("AuthenticationMethod=None fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "arr_config_none.xml"),
			parseArrConfig,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseArrConfig did not recognise fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "arr-config" {
			t.Fatalf("SchemaID=%q, want arr-config", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC010" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC010: want failing finding for AuthenticationMethod=None; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("AuthenticationMethod=Forms passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "arr_config_forms_auth.xml"),
			parseArrConfig,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseArrConfig did not recognise forms-auth fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC010" && f.IsFail() {
				t.Errorf("SVC010: must NOT fire for AuthenticationMethod=Forms; got %+v", f)
			}
		}
	})
}

func TestSVC010_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC010")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC010: want NotAssessed when Collector==nil, got %+v", findings)
	}
}

// TestSVC010_ParserFed_ArrAbsentAuth verifies that an *arr config.xml without
// any <AuthenticationMethod> element is treated as None (the legacy implied
// default) and SVC010 fires — not silently passes.
func TestSVC010_ParserFed_ArrAbsentAuth(t *testing.T) {
	c := findRegisteredCheck(t, "SVC010")

	fact := collectConfigInternal(
		filepath.Join("testdata", "arr_config_noauth_absent.xml"),
		parseArrConfig,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseArrConfig did not recognise absent-auth fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "arr-config" {
		t.Fatalf("SchemaID=%q, want arr-config", fact.SchemaID)
	}
	// Bug (a): absent AuthenticationMethod must default to "None", not "".
	if fact.Values["AuthenticationMethod"] != "None" {
		t.Errorf("parseArrConfig: AuthenticationMethod=%q, want None (absent=legacy None)", fact.Values["AuthenticationMethod"])
	}

	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC010" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC010: want failing finding for absent AuthenticationMethod (implicit None); got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC011_ParserFed_NoAuth(t *testing.T) {
	c := findRegisteredCheck(t, "SVC011")

	t.Run("LocalHostAuth=false fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "qbittorrent_noauth.conf"),
			parseQBittorrentConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseQBittorrentConf did not recognise fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "qbittorrent-conf" {
			t.Fatalf("SchemaID=%q, want qbittorrent-conf", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC011" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC011: want failing finding for webui.auth=false; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("LocalHostAuth=true passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "qbittorrent_auth.conf"),
			parseQBittorrentConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseQBittorrentConf did not recognise auth fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC011" && f.IsFail() {
				t.Errorf("SVC011: must NOT fire for LocalHostAuth=true; got %+v", f)
			}
		}
	})
}

// TestSVC010_ParserFed_PortExtracted verifies R2-7: parseArrConfig must emit
// the <Port> element value in Values["Port"] so SVC010 can use it as the
// finding port rather than hardcoding 7878 for all *arr variants.
func TestSVC010_ParserFed_PortExtracted(t *testing.T) {
	// arr_config_none.xml has <Port>8989</Port> (Sonarr).
	fact := collectConfigInternal(
		filepath.Join("testdata", "arr_config_none.xml"),
		parseArrConfig,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false; values: %v", fact.Values)
	}
	// R2-7 contract: Port must be present in Values.
	port, ok := fact.Values["Port"]
	if !ok || port == "" {
		t.Errorf("parseArrConfig: Values[\"Port\"] absent/empty, want \"8989\"; values: %v", fact.Values)
	} else if port != "8989" {
		t.Errorf("parseArrConfig: Values[\"Port\"]=%q, want \"8989\"", port)
	}

	// arr_config_noauth_absent.xml has <Port>7878</Port> (Radarr).
	factRadarr := collectConfigInternal(
		filepath.Join("testdata", "arr_config_noauth_absent.xml"),
		parseArrConfig,
	)
	if !factRadarr.SchemaKnown {
		t.Fatalf("SchemaKnown=false for radarr fixture; values: %v", factRadarr.Values)
	}
	portR, okR := factRadarr.Values["Port"]
	if !okR || portR == "" {
		t.Errorf("parseArrConfig: Values[\"Port\"] absent/empty for radarr fixture, want \"7878\"; values: %v", factRadarr.Values)
	} else if portR != "7878" {
		t.Errorf("parseArrConfig: Values[\"Port\"]=%q, want \"7878\"", portR)
	}
}

// TestSVC010_FindingPort_UsesConfigPort verifies R2-7: the SVC010 finding
// Metadata["port"] must reflect the port from the config, not the hardcoded 7878.
func TestSVC010_FindingPort_UsesConfigPort(t *testing.T) {
	c := findRegisteredCheck(t, "SVC010")
	// arr_config_none.xml has AuthenticationMethod=None and Port=8989 (Sonarr).
	fact := collectConfigInternal(
		filepath.Join("testdata", "arr_config_none.xml"),
		parseArrConfig,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false; values: %v", fact.Values)
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC010" && f.IsFail() {
			port := f.Metadata["port"]
			if port != "8989" {
				t.Errorf("SVC010 Metadata[\"port\"]=%q, want \"8989\" (from <Port> in config.xml); R2-7 bug: svc010 hardcodes 7878", port)
			}
			return
		}
	}
	t.Fatalf("SVC010: want failing finding for AuthenticationMethod=None; got %+v", findings)
}

// TestSVC010_PerImagePortFallback verifies R3-4: when config.xml omits <Port>,
// SVC010 must use the per-image default port from ctx.Stack's service image,
// NOT hardcode 7878 for all *arr variants.
//
// Test cases cover sonarr (8989), prowlarr (9696), lidarr (8686), readarr (8787),
// and radarr (7878 — the generic fallback, so this also passes before the fix).
func TestSVC010_PerImagePortFallback(t *testing.T) {
	c := findRegisteredCheck(t, "SVC010")

	// arr_config_none_noport.xml has AuthenticationMethod=None but NO <Port>.
	fact := collectConfigInternal(
		filepath.Join("testdata", "arr_config_none_noport.xml"),
		parseArrConfig,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseArrConfig did not recognise no-port fixture; values: %v", fact.Values)
	}
	if _, ok := fact.Values["Port"]; ok {
		t.Fatalf("fixture must NOT emit Port but got %q; fix the fixture", fact.Values["Port"])
	}

	cases := []struct {
		image    string
		wantPort string
	}{
		{"linuxserver/sonarr:latest", "8989"},
		{"linuxserver/prowlarr:latest", "9696"},
		{"linuxserver/lidarr:latest", "8686"},
		{"linuxserver/readarr:latest", "8787"},
		{"linuxserver/radarr:latest", "7878"},
		// Generic fallback: unknown *arr image → 7878
		{"unknown/arr:latest", "7878"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.image, func(t *testing.T) {
			stack := &model.Stack{
				Services: []*model.Service{
					{
						Name:  "arr",
						Image: tc.image,
						Ports: []model.PortMapping{
							{HostPort: mustAtoi(tc.wantPort), ContainerPort: mustAtoi(tc.wantPort), Protocol: "tcp"},
						},
					},
				},
			}
			ctx := &model.ScanContext{
				Stack:     stack,
				Collector: &model.Signals{Configs: []model.ConfigFact{fact}},
			}
			findings := c.Run(ctx)
			var fail *model.Finding
			for i := range findings {
				if findings[i].CheckID == "SVC010" && findings[i].IsFail() {
					fail = &findings[i]
					break
				}
			}
			if fail == nil {
				t.Fatalf("SVC010: want failing finding (AuthenticationMethod=None); got %+v", findings)
			}
			port := fail.Metadata["port"]
			if port != tc.wantPort {
				t.Errorf("SVC010 Metadata[\"port\"]=%q, want %q for image %q (R3-4: per-image fallback)",
					port, tc.wantPort, tc.image)
			}
		})
	}
}

// TestSVC010_ParserFed_NestedPortIgnored verifies R3-5: a deeply nested <Port>
// element (e.g. Config.Nested.Port) must NOT be treated as the service port.
// Only direct root children (Config.Port, strings.Count=="1") are eligible.
func TestSVC010_ParserFed_NestedPortIgnored(t *testing.T) {
	// arr_config_nested_port.xml has NO direct <Port> child of <Config>,
	// only a deeply nested <Nested><Port>9999</Port></Nested>.
	fact := collectConfigInternal(
		filepath.Join("testdata", "arr_config_nested_port.xml"),
		parseArrConfig,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseArrConfig did not recognise fixture; values: %v", fact.Values)
	}
	if port, ok := fact.Values["Port"]; ok {
		t.Errorf("parseArrConfig: Values[\"Port\"]=%q, want absent — nested Port must not be emitted (R3-5)", port)
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			panic("mustAtoi: not a digit: " + s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func TestSVC011_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC011")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC011: want NotAssessed when Collector==nil, got %+v", findings)
	}
}
