package engine_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/model"

	_ "github.com/jakelamon/keelix/internal/checks/all"
)

// buildAIAgentSignals constructs a *model.Signals that triggers:
//   - AGT001 (auto-approval): openclaw tools.exec.ask == "off"
//   - AGT002 (lethal trifecta): fs.workspaceOnly == "false" (private data leg)
//   - browser.enabled == "true" (untrusted-ingest leg)
//   - mcpServers.slack-exfil.command present (exfil leg, messaging keyword)
//
// AGT002 is Fatal in the catalog, so the autonomy cap must drive the overall
// rating to RED regardless of the numeric band.
func buildAIAgentSignals() *model.Signals {
	return &model.Signals{
		Version:  model.SignalsVersion,
		Platform: model.Platform{OS: "darwin"},
		Configs: []model.ConfigFact{
			{
				Source:      "/Users/testuser/.openclaw/openclaw.json",
				Mode:        "0600",
				SchemaID:    "openclaw-config",
				SchemaKnown: true,
				Values: map[string]string{
					// AGT001 trigger: auto-approval
					"tools.exec.ask":      "off",
					"tools.exec.security": "sandboxed",
					"tools.profile":       "default",
					// AGT002 trigger: lethal-trifecta legs
					// leg 1: private-data — tools.fs.workspaceOnly is the key the check reads
					"tools.fs.workspaceOnly":       "false",
					"agents.defaults.sandbox.mode": "off",
					// leg 2: untrusted-ingest
					"browser.enabled":           "true",
					"tools.web.search.provider": "bing",
					// inbound channel policy (AGT009)
					"channels.discord.groupPolicy": "open",
					"channels.telegram.dmPolicy":   "open",
					// leg 3: exfil — messaging MCP server
					"mcpServers.slack-exfil.command":         "npx",
					"mcpServers.slack-exfil.args.0":          "@slack/mcp-server",
					"mcpServers.slack-exfil.env.SLACK_TOKEN": "[secret]",
				},
			},
		},
	}
}

// writeSignalsFixture marshals sig to JSON and writes it to path.
func writeSignalsFixture(t *testing.T, path string, sig *model.Signals) {
	t.Helper()
	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("json.Marshal signals: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile %s: %v", path, err)
	}
}

// findingIDs returns all check IDs from r.Findings for use in test diagnostics.
func findingIDs(r *model.Result) []string {
	ids := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		ids = append(ids, f.CheckID)
	}
	return ids
}

// TestEngineIntegration_AIAgentFindings verifies the full pipeline:
// given a Collector with an OpenClaw config that has auto-approval and all
// three lethal-trifecta legs, the engine must produce AGT001 + AGT002,
// overall RED rating via the autonomy cap, and leave the network sub-score
// group unaffected.
func TestEngineIntegration_AIAgentFindings(t *testing.T) {
	sig := buildAIAgentSignals()
	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "signals.json")
	writeSignalsFixture(t, sigPath, sig)

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

	// 1. AGT001 must be present as a Critical finding.
	if !hasFinding(r, "AGT001", model.SeverityCritical) {
		t.Errorf("expected AGT001 Critical (auto-approval) finding; got IDs: %v", findingIDs(r))
	}

	// 2. AGT002 must be present as a Critical finding.
	if !hasFinding(r, "AGT002", model.SeverityCritical) {
		t.Errorf("expected AGT002 Critical (lethal trifecta) finding; got IDs: %v", findingIDs(r))
	}

	// 3. Overall rating must be RED (autonomy cap from Fatal AGT002).
	if r.Rating != "RED" {
		t.Errorf("overall rating = %q; want RED (autonomy cap)", r.Rating)
	}

	// 4. CapDriver must name the autonomy reason.
	if r.CapDriver == nil {
		t.Fatal("CapDriver is nil; expected autonomy cap from AGT002")
	}
	const wantReason = "dangerous AI agent / MCP capability"
	if r.CapDriver.Reason != wantReason {
		t.Errorf("CapDriver.Reason = %q; want %q", r.CapDriver.Reason, wantReason)
	}
	if r.CapDriver.Grade != "RED" {
		t.Errorf("CapDriver.Grade = %q; want RED", r.CapDriver.Grade)
	}

	// 5. GroupExposure sub-score must be >= 85 (clean stack, network group unaffected).
	for _, gs := range r.SubScores {
		if gs.Group == model.GroupExposure && gs.Score < 85 {
			t.Errorf("GroupExposure sub-score = %d; want >= 85 (clean stack, network unaffected)", gs.Score)
		}
	}

	// 6. GroupAIAgent sub-score must be present and degraded.
	var aiScore *model.GroupScore
	for i := range r.SubScores {
		if r.SubScores[i].Group == model.GroupAIAgent {
			aiScore = &r.SubScores[i]
			break
		}
	}
	if aiScore == nil {
		t.Error("GroupAIAgent not present in SubScores")
	} else if aiScore.Score >= 100 {
		// AI/MCP findings are Localhost-scoped (0.10× multiplier), so even with two
		// failing findings the sub-score is typically in the 90s — not below 85.
		// The important invariant is that the score is degraded from 100 (not perfect),
		// confirming the failing findings enter the ratio. RFX-7: before the fix,
		// Classify inflated ExposureUnknown (0.50×) artificially pushed the score below
		// 85; the correct Localhost (0.10×) keeps the score in the 90s.
		t.Errorf("GroupAIAgent sub-score = %d; want < 100 (has failing findings, score must be degraded)", aiScore.Score)
	}

	// 7. ScoringModel must be "v2" (regression guard).
	if r.ScoringModel != "v2" {
		t.Errorf("ScoringModel = %q; want v2", r.ScoringModel)
	}
}
