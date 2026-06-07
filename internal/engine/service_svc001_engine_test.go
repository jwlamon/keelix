package engine_test

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

// TestEngineIntegration_SVC001_RedisNoAuth_RedCap verifies the complete pipeline:
//
//  1. A compose file with a Redis service publishing port 6379 to 0.0.0.0.
//  2. A Signals file containing a redis-conf ConfigFact with the three decisive
//     keys (requirepass.present=false, protected-mode=no, bind=0.0.0.0) that
//     the real parseRedisConf parser emits.
//  3. SVC001 must fire as Critical+Fatal.
//  4. The overall rating must be RED (fatal SVC001 cap via public port).
//  5. GroupService sub-score must be present and degraded.
func TestEngineIntegration_SVC001_RedisNoAuth_RedCap(t *testing.T) {
	// Build a Signals document with a redis-conf ConfigFact.
	// The Values keys are PINNED to the contract: they must exactly match
	// what parseRedisConf emits and what SVC001.Run reads.
	sig := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Now().UTC(),
		Platform:    model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				Source:      "/srv/redis/redis.conf",
				Mode:        "0644",
				SchemaID:    "redis-conf",
				SchemaKnown: true,
				Values: map[string]string{
					// PINNED contract keys emitted by parseRedisConf:
					"requirepass.present": "false",
					"protected-mode":      "no",
					"bind":                "0.0.0.0",
				},
			},
		},
	}

	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "signals.json")
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal signals: %v", err)
	}
	if err := os.WriteFile(sigPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile signals: %v", err)
	}

	// Use the redis-compose fixture which publishes port 6379 to 0.0.0.0.
	composePath := filepath.Join("testdata", "redis-compose", "docker-compose.yml")

	in := engine.Input{
		ComposePath: composePath,
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: sigPath,
		},
	}

	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	// 1. SVC001 must be present as Critical.
	if !hasFinding(r, "SVC001", model.SeverityCritical) {
		t.Errorf("expected SVC001 Critical; got IDs: %v", findingIDs(r))
	}

	// 2. Overall rating must be RED (fatal SVC001 cap).
	if r.Rating != "RED" {
		t.Errorf("rating = %q; want RED (SVC001 fatal cap)", r.Rating)
	}

	// 3. CapDriver must name SVC001.
	if r.CapDriver == nil {
		t.Fatal("CapDriver is nil; expected SVC001 fatal cap")
	}
	if r.CapDriver.CheckID != "SVC001" {
		t.Errorf("CapDriver.CheckID = %q; want SVC001", r.CapDriver.CheckID)
	}

	// 4. GroupService sub-score must be present and degraded from 100.
	var svcScore *model.GroupScore
	for i := range r.SubScores {
		if r.SubScores[i].Group == model.GroupService {
			svcScore = &r.SubScores[i]
			break
		}
	}
	if svcScore == nil {
		t.Error("GroupService not present in SubScores")
	} else if svcScore.Score >= 100 {
		t.Errorf("GroupService sub-score = %d; want < 100 (SVC001 failing)", svcScore.Score)
	}

	// 5. ScoringModel must be v2.
	if r.ScoringModel != "v2" {
		t.Errorf("ScoringModel = %q; want v2", r.ScoringModel)
	}
}

// TestEngineIntegration_SVC001_NamedVolume_NotAssessed verifies that when the
// redis service uses a NAMED volume (not a bind mount), the engine has no
// config to read and SVC001 returns NotAssessed rather than a false negative
// pass. The absence of a redis-conf ConfigFact in Signals must produce
// StatusNotAssessed for SVC001.
func TestEngineIntegration_SVC001_NamedVolume_NotAssessed(t *testing.T) {
	// Signals with NO redis-conf ConfigFact (simulates named-volume opacity).
	sig := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Now().UTC(),
		Platform:    model.Platform{OS: "linux"},
		Configs:     []model.ConfigFact{}, // no redis-conf
	}

	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "signals_namedvol.json")
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(sigPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	in := engine.Input{
		ComposePath: filepath.Join("testdata", "redis-compose", "docker-compose.yml"),
		Options: model.ScanOptions{
			NoProbe:     true,
			SignalsPath: sigPath,
		},
	}

	r, err := engine.Scan(context.Background(), in)
	if err != nil {
		t.Fatalf("engine.Scan: %v", err)
	}

	// SVC001 must not fire as a scored failure when config is unavailable.
	// IsFail checks severity only; also require StatusAssessed to distinguish
	// a real failure from a NotAssessed finding (which retains its catalog severity).
	for _, f := range r.Findings {
		if f.CheckID == "SVC001" && f.IsFail() && f.Status == model.StatusAssessed {
			t.Errorf("SVC001 must not fire as a failure when redis-conf is absent; got: %+v", f)
		}
	}

	// SVC001 must appear in NotAssessed or as a passing/not-assessed finding.
	foundNA := false
	for _, f := range r.NotAssessed {
		if f.CheckID == "SVC001" {
			foundNA = true
			break
		}
	}

	// Also check Findings slice (some checks return NotAssessed via Findings, not NotAssessed slice).
	if !foundNA {
		for _, f := range r.Findings {
			if f.CheckID == "SVC001" && f.Status == model.StatusNotAssessed {
				foundNA = true
				break
			}
		}
	}
	if !foundNA {
		t.Errorf("SVC001 must be NotAssessed when redis-conf ConfigFact is absent; "+
			"NotAssessed IDs: %v, all finding IDs: %v",
			notAssessedIDs(r), findingIDs(r))
	}
}

func notAssessedIDs(r *model.Result) []string {
	out := make([]string, 0, len(r.NotAssessed))
	for _, f := range r.NotAssessed {
		out = append(out, f.CheckID)
	}
	return out
}
