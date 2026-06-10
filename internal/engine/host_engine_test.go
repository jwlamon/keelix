package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/model"

	_ "github.com/jakelamon/keelix/internal/checks/all"
)

// buildSSHEffectiveSignals returns a *model.Signals that triggers HST003:
//   - sshd-effective ConfigFact with _source=effective, passwordauthentication=yes,
//     permitrootlogin=yes (both HST001 and HST002 legs true)
//   - A ListeningSocket for sshd bound to 0.0.0.0:22 (non-loopback — internet-exposed leg)
//
// HST003 is Fatal (BaseImpact 8.5) so the overall cap must be RED regardless
// of the numeric band.
func buildSSHEffectiveSignals() *model.Signals {
	return &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Now().UTC(),
		Platform:    model.Platform{OS: "linux", Distro: "debian", Version: "12"},
		Privilege:   model.Privilege{Root: true, EUID: 0},
		Sockets: []model.ListeningSocket{
			{Proto: "tcp", Bind: "0.0.0.0", Port: 22, Comm: "sshd"},
		},
		Configs: []model.ConfigFact{
			{
				Source:      "/proc/self/sshd-T",
				Mode:        "0000",
				SchemaID:    "sshd-effective",
				SchemaKnown: true,
				Values: map[string]string{
					"_source":                "effective",
					"permitrootlogin":        "yes",
					"passwordauthentication": "yes",
					"pubkeyauthentication":   "yes",
					"permitemptypasswords":   "no",
					"maxauthtries":           "6",
					"logingracetime":         "120",
					"x11forwarding":          "no",
					"port":                   "22",
				},
			},
		},
	}
}

// TestEngineIntegration_HST003_RedCap verifies the full pipeline:
// given a Collector with an sshd-effective ConfigFact that has password auth
// and root login enabled, plus a non-loopback socket on port 22, the engine
// must produce HST003 Critical, overall RED rating via the fatal host-OS cap,
// a GroupHost sub-score that is degraded, and leave GroupExposure unaffected.
func TestEngineIntegration_HST003_RedCap(t *testing.T) {
	sig := buildSSHEffectiveSignals()

	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "signals.json")

	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal signals: %v", err)
	}
	if err := os.WriteFile(sigPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile %s: %v", sigPath, err)
	}

	in := engine.Input{
		ComposePath: filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: sigPath,
		},
	}

	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	// 1. HST003 must be present as a Critical finding.
	if !hasFinding(r, "HST003", model.SeverityCritical) {
		t.Errorf("expected HST003 Critical finding; got IDs: %v", findingIDs(r))
	}

	// 2. Overall rating must be RED (fatal host-OS cap from HST003).
	if r.Rating != "RED" {
		t.Errorf("overall rating = %q; want RED (fatal HST003 cap)", r.Rating)
	}

	// 3. CapDriver must name HST003.
	if r.CapDriver == nil {
		t.Fatal("CapDriver is nil; expected host-OS cap from HST003")
	}
	if r.CapDriver.CheckID != "HST003" {
		t.Errorf("CapDriver.CheckID = %q; want HST003", r.CapDriver.CheckID)
	}
	if r.CapDriver.Grade != "RED" {
		t.Errorf("CapDriver.Grade = %q; want RED", r.CapDriver.Grade)
	}

	// 4. GroupHost sub-score must be present and degraded from 100.
	var hostScore *model.GroupScore
	for i := range r.SubScores {
		if r.SubScores[i].Group == model.GroupHost {
			hostScore = &r.SubScores[i]
			break
		}
	}
	if hostScore == nil {
		t.Error("GroupHost not present in SubScores")
	} else if hostScore.Score >= 100 {
		t.Errorf("GroupHost sub-score = %d; want < 100 (has failing findings)", hostScore.Score)
	}

	// 5. GroupExposure sub-score must be >= 85 (clean stack, unaffected by host findings).
	for _, gs := range r.SubScores {
		if gs.Group == model.GroupExposure && gs.Score < 85 {
			t.Errorf("GroupExposure sub-score = %d; want >= 85 (clean stack, unaffected)", gs.Score)
		}
	}

	// 6. ScoringModel must be "v2".
	if r.ScoringModel != "v2" {
		t.Errorf("ScoringModel = %q; want v2", r.ScoringModel)
	}
}

// TestEngineIntegration_HST003_StaticSource_NoFatal verifies that HST003 does
// NOT fire as Fatal (and does not set CapDriver=HST003) when _source=static,
// because the static parse path has insufficient confidence for the Fatal cap.
// HST001 and HST002 may still fire individually as Warnings, but no RED cap.
func TestEngineIntegration_HST003_StaticSource_NoFatal(t *testing.T) {
	sig := buildSSHEffectiveSignals()
	// Override to static source — HST003 must not fire the Fatal cap.
	sig.Configs[0].Values["_source"] = "static"

	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "signals_static.json")

	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal signals: %v", err)
	}
	if err := os.WriteFile(sigPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile %s: %v", sigPath, err)
	}

	in := engine.Input{
		ComposePath: filepath.Join("..", "..", "testdata", "clean", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: sigPath,
		},
	}

	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	// HST003 must not be the CapDriver when source is static.
	if r.CapDriver != nil && r.CapDriver.CheckID == "HST003" {
		t.Errorf("CapDriver = HST003 on static-source scan; Fatal must not fire off inferred static default")
	}
}
