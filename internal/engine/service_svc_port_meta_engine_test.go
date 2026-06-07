package engine_test

// TestEngineIntegration_FIX6_SVC010_PortMetadata verifies the FIX-6 contract:
// SVC010 (and by extension all SVC0NN checks fixed in the same pass) must set
// f.Metadata["port"] on fired findings so classifyOne can resolve the
// ExposureClass from the declared publish in the compose file.
//
// Two sub-tests:
//
//  1. PublishedPort: *arr NoAuth with port 7878 published to 0.0.0.0.
//     The finding must classify as ExposureInternet (not ExposureUnknown).
//     With SeverityCritical + ConfidenceHigh + ExposureInternet → YELLOW cap.
//
//  2. ContainerInternal: *arr NoAuth with NO published port.
//     Without a host-port declaration or socket evidence, the finding must
//     stay ExposureUnknown (0.5× multiplier, no cap).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jwlamon/keelix/internal/engine"
	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// arrSignals returns a Signals file path with a single arr-config ConfigFact
// whose values reproduce what parseArrConfig emits for an unauthenticated arr.
// Port=7878 is explicitly included to test the "Port present in config" path (R2-7);
// the "Port absent" path (R3-4 per-image fallback) is tested by arrNoPortSignals.
func arrSignals(t *testing.T) string {
	t.Helper()
	sig := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Now().UTC(),
		Platform:    model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				Source:      "/config/config.xml",
				Mode:        "0644",
				SchemaID:    "arr-config",
				SchemaKnown: true,
				// PINNED contract keys emitted by parseArrConfig for AuthenticationMethod=None.
				// Port=7878 is explicit so R3-4 per-image fallback does not apply here.
				Values: map[string]string{
					"AuthenticationMethod": "None",
					"Port":                 "7878",
				},
			},
		},
	}
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal arr signals: %v", err)
	}
	p := filepath.Join(t.TempDir(), "arr_signals.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile arr signals: %v", err)
	}
	return p
}

// TestEngineIntegration_FIX6_SVC010_PublishedPort_InternetExposure verifies
// that when SVC010 fires and the compose file publishes port 7878 to 0.0.0.0,
// the finding's ExposureClass is ExposureInternet (requires Metadata["port"]).
func TestEngineIntegration_FIX6_SVC010_PublishedPort_InternetExposure(t *testing.T) {
	r, err := engine.Scan(context.Background(), engine.Input{
		ComposePath: filepath.Join("testdata", "arr-compose", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: arrSignals(t),
		},
	})
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	// Find the SVC010 finding.
	var svc010 *model.Finding
	for i := range r.Findings {
		if r.Findings[i].CheckID == "SVC010" && r.Findings[i].IsFail() {
			svc010 = &r.Findings[i]
			break
		}
	}
	if svc010 == nil {
		t.Fatalf("SVC010 did not fire; findings: %v", findingIDs(r))
	}

	// FIX-6 contract: Metadata["port"] must be set so classifyOne can work.
	if svc010.Metadata == nil || svc010.Metadata["port"] == "" {
		t.Errorf("SVC010 finding has no Metadata[\"port\"]; classifyOne cannot classify (FIX-6 bug)")
	}

	// With port metadata + published 7878→0.0.0.0, classifyOne must resolve
	// ExposureInternet (not ExposureUnknown).
	if svc010.ExposureClass != model.ExposureInternet {
		t.Errorf("SVC010 ExposureClass = %v; want ExposureInternet (published 7878→0.0.0.0)", svc010.ExposureClass)
	}

	// Critical + ConfidenceHigh + Internet + no mitigations → YELLOW cap.
	// (SVC010 is not Fatal, so RED is not expected — YELLOW is the correct floor.)
	if r.Rating == "GREEN" {
		t.Errorf("rating = GREEN; want YELLOW (SVC010 Critical Internet no-auth should cap at YELLOW)")
	}
}

// sonarrSignals returns a Signals file path whose arr-config ConfigFact
// includes Port=8989 (Sonarr's default) in addition to AuthenticationMethod=None.
// This is the post-R2-7-fix output of parseArrConfig for a Sonarr config.xml.
func sonarrSignals(t *testing.T) string {
	t.Helper()
	sig := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Now().UTC(),
		Platform:    model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				Source:      "/config/config.xml",
				Mode:        "0644",
				SchemaID:    "arr-config",
				SchemaKnown: true,
				// R2-7: parseArrConfig must emit Port so SVC010 uses it.
				Values: map[string]string{
					"AuthenticationMethod": "None",
					"Port":                 "8989",
				},
			},
		},
	}
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal sonarr signals: %v", err)
	}
	p := filepath.Join(t.TempDir(), "sonarr_signals.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile sonarr signals: %v", err)
	}
	return p
}

// TestEngineIntegration_R2_7_SVC010_SonarrPort_NotUnknown verifies R2-7:
// when SVC010 fires for a Sonarr instance (port 8989) published as 8989:8989,
// the finding classifies as something other than ExposureUnknown.
// Before the fix, svc010 hardcodes port=7878 so 8989:8989 never matches →
// declaredPublic(stack, 7878)=false → ExposureUnknown.
// After the fix, port=8989 → declaredPublic(stack, 8989)=true → ExposureFiltered
// (sonarr:8989 is an intel-expected public port, so intent marks it Filtered).
func TestEngineIntegration_R2_7_SVC010_SonarrPort_NotUnknown(t *testing.T) {
	r, err := engine.Scan(context.Background(), engine.Input{
		ComposePath: filepath.Join("testdata", "arr-sonarr-compose", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: sonarrSignals(t),
		},
	})
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	var svc010 *model.Finding
	for i := range r.Findings {
		if r.Findings[i].CheckID == "SVC010" && r.Findings[i].IsFail() {
			svc010 = &r.Findings[i]
			break
		}
	}
	if svc010 == nil {
		t.Fatalf("SVC010 did not fire; findings: %v", findingIDs(r))
	}

	// R2-7: SVC010 must set Metadata["port"]="8989" (from config, not hardcoded 7878).
	if svc010.Metadata == nil || svc010.Metadata["port"] == "" {
		t.Errorf("SVC010 finding has no Metadata[\"port\"]")
	} else if svc010.Metadata["port"] != "8989" {
		t.Errorf("SVC010 Metadata[\"port\"]=%q, want \"8989\" (R2-7: svc010 must use Port from config)", svc010.Metadata["port"])
	}

	// R2-7 root cause: with hardcoded 7878, declaredPublic(stack, 7878)=false for
	// a sonarr 8989:8989 compose → ExposureUnknown. After the fix, port=8989 is used
	// → declaredPublic(stack, 8989)=true → ExposureFiltered (sonarr:8989 is intel-
	// expected, so intent marks it as Filtered rather than Internet). Either way,
	// the ExposureClass must NOT be ExposureUnknown.
	if svc010.ExposureClass == model.ExposureUnknown {
		t.Errorf("SVC010 ExposureClass = ExposureUnknown; want non-Unknown (published 8989:8989 must be classified; R2-7 bug: hardcoded 7878 caused Unknown)")
	}
}

// arrNoPortSignals returns a Signals file path whose arr-config ConfigFact has
// AuthenticationMethod=None but NO Port key — simulating a config.xml that
// omits <Port> entirely. SVC010 must fall back to the per-image default.
func arrNoPortSignals(t *testing.T) string {
	t.Helper()
	sig := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Now().UTC(),
		Platform:    model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				Source:      "/config/config.xml",
				Mode:        "0644",
				SchemaID:    "arr-config",
				SchemaKnown: true,
				// No "Port" key — simulates a config.xml that omits <Port>.
				// R3-4: svc010 must infer the port from the stack image.
				Values: map[string]string{
					"AuthenticationMethod": "None",
				},
			},
		},
	}
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal arrNoPort signals: %v", err)
	}
	p := filepath.Join(t.TempDir(), "arr_noport_signals.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile arrNoPort signals: %v", err)
	}
	return p
}

// TestEngineIntegration_R3_4_PerImagePortFallback verifies R3-4:
// when arr config.xml omits <Port>, SVC010 must fall back to the per-image
// default port (sonarr=8989, prowlarr=9696, lidarr=8686, readarr=8787,
// radarr=7878) from the stack image, NOT hardcode 7878 for all variants.
//
// Each sub-test uses a compose file that publishes the correct per-image port,
// so after the fix the finding's Metadata["port"] matches and ExposureClass is
// not ExposureUnknown. Before the fix all non-radarr variants get port=7878 →
// the declared publish (e.g. 8989:8989) never matches → ExposureUnknown.
func TestEngineIntegration_R3_4_PerImagePortFallback(t *testing.T) {
	cases := []struct {
		name     string
		compose  string
		wantPort string
	}{
		{"sonarr", "arr-sonarr-noport", "8989"},
		{"prowlarr", "arr-prowlarr-noport", "9696"},
		{"lidarr", "arr-lidarr-noport", "8686"},
		{"readarr", "arr-readarr-noport", "8787"},
		{"radarr", "arr-radarr-noport", "7878"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r, err := engine.Scan(context.Background(), engine.Input{
				ComposePath: filepath.Join("testdata", tc.compose, "docker-compose.yml"),
				Options: model.ScanOptions{
					NoProbe:     true,
					SignalsPath: arrNoPortSignals(t),
				},
			})
			if err != nil {
				t.Fatalf("engine.Scan: %v", err)
			}

			var svc010 *model.Finding
			for i := range r.Findings {
				if r.Findings[i].CheckID == "SVC010" && r.Findings[i].IsFail() {
					svc010 = &r.Findings[i]
					break
				}
			}
			if svc010 == nil {
				t.Fatalf("SVC010 did not fire; findings: %v", findingIDs(r))
			}

			// R3-4: port must be the per-image default, not hardcoded 7878.
			if svc010.Metadata == nil || svc010.Metadata["port"] == "" {
				t.Errorf("SVC010 Metadata[\"port\"] is absent")
			} else if svc010.Metadata["port"] != tc.wantPort {
				t.Errorf("SVC010 Metadata[\"port\"]=%q, want %q (R3-4: wrong per-image fallback; all images must not use 7878)",
					svc010.Metadata["port"], tc.wantPort)
			}

			// With the correct port in metadata and it published to the host, the
			// ExposureClass must NOT be ExposureUnknown.
			if svc010.ExposureClass == model.ExposureUnknown {
				t.Errorf("SVC010 ExposureClass = ExposureUnknown; want non-Unknown (correct port %s published to host; R3-4: wrong fallback port caused Unknown)",
					tc.wantPort)
			}
		})
	}
}

// TestEngineIntegration_FIX6_SVC010_ContainerInternal_UnknownExposure verifies
// that when the *arr port is NOT published to the host, ExposureClass stays
// ExposureUnknown (0.5× multiplier, no RED/YELLOW cap from exposure).
func TestEngineIntegration_FIX6_SVC010_ContainerInternal_UnknownExposure(t *testing.T) {
	r, err := engine.Scan(context.Background(), engine.Input{
		ComposePath: filepath.Join("testdata", "arr-internal", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: arrSignals(t),
		},
	})
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	var svc010 *model.Finding
	for i := range r.Findings {
		if r.Findings[i].CheckID == "SVC010" && r.Findings[i].IsFail() {
			svc010 = &r.Findings[i]
			break
		}
	}
	if svc010 == nil {
		t.Fatalf("SVC010 did not fire; findings: %v", findingIDs(r))
	}

	// Container-internal: no host port → ExposureUnknown (cannot upgrade without
	// probe confirmation or socket evidence).
	if svc010.ExposureClass != model.ExposureUnknown {
		t.Errorf("SVC010 ExposureClass = %v; want ExposureUnknown (no published port, no probe)", svc010.ExposureClass)
	}
}
