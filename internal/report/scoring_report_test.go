package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/report"
)

// v2Result extends sampleResult() with v2 scoring roll-up data.
//
// The numeric score is placed in the GREEN band (>=85) and the cap is RED, so
// the engine would set CapDriver (grade < band) and the CAP line is rendered.
// This is the only engine-reachable state where a CapDriver appears: the
// numeric score is green but a cap finding forces the overall rating to RED.
func v2Result() *model.Result {
	r := sampleResult()
	// Override Score/Rating to the cap-scenario: numeric=GREEN, capped to RED.
	r.Score = 90
	r.Rating = "RED"
	r.ScoringModel = "v2"
	r.SubScores = []model.GroupScore{
		{Group: model.GroupExposure, Score: 90, NotAssessed: 0},
		{Group: model.GroupTLS, Score: 100, NotAssessed: 1},
	}
	r.CapDriver = &model.CapDriver{
		CheckID: "EXP001",
		Title:   "PostgreSQL reachable from the internet (port 5432)",
		Reason:  "fatal internet-exposed datastore with no mitigations",
		Grade:   "RED",
	}
	r.NotAssessed = []model.Finding{
		{
			CheckID: "PKG010",
			Title:   "Security updates pending (not assessed: collection disabled)",
			Status:  model.StatusNotAssessed,
		},
	}
	return r
}

func TestTerminal_v2_capAndNotAssessed(t *testing.T) {
	var buf bytes.Buffer
	r := v2Result()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Scoring model: v2") {
		t.Errorf("expected 'Scoring model: v2' in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "Network Exposure") || !strings.Contains(out, "90/100") {
		t.Errorf("expected sub-score 'Network Exposure ... 90/100'; got:\n%s", out)
	}
	if !strings.Contains(out, "CAP: EXP001 PostgreSQL reachable from the internet (port 5432) — fatal internet-exposed datastore with no mitigations (grade capped to RED)") {
		t.Errorf("expected prominent CAP line; got:\n%s", out)
	}
	if !strings.Contains(out, "Not assessed (1)") {
		t.Errorf("expected 'Not assessed (1)' section header; got:\n%s", out)
	}
	if !strings.Contains(out, "Security updates pending (not assessed: collection disabled)") {
		t.Errorf("expected not-assessed title listed; got:\n%s", out)
	}
}

func TestMarkdown_v2_subScoresCapNotAssessed(t *testing.T) {
	var buf bytes.Buffer
	r := v2Result()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "## Scoring Breakdown (v2)") {
		t.Errorf("expected '## Scoring Breakdown (v2)' section; got:\n%s", out)
	}
	if !strings.Contains(out, "| Group | Sub-Score | Not Assessed |") {
		t.Errorf("expected sub-scores table header; got:\n%s", out)
	}
	if !strings.Contains(out, "| Network Exposure | 90/100 | 0 |") {
		t.Errorf("expected Network Exposure sub-score row; got:\n%s", out)
	}
	if !strings.Contains(out, "> **Grade cap:** `EXP001` PostgreSQL reachable from the internet (port 5432) — fatal internet-exposed datastore with no mitigations (capped to **RED**)") {
		t.Errorf("expected cap-driver callout; got:\n%s", out)
	}
	if !strings.Contains(out, "### Not Assessed") {
		t.Errorf("expected '### Not Assessed' section (nested under ## Scoring Breakdown); got:\n%s", out)
	}
	if !strings.Contains(out, "- **Security updates pending (not assessed: collection disabled)** (`PKG010`)") {
		t.Errorf("expected not-assessed list item; got:\n%s", out)
	}
}

// aiMcpCapResult builds a Result whose SubScores include the two new SP1a
// groups and whose CapDriver carries the autonomy-cap reason. The numeric
// score is in the GREEN band (92) so a CapDriver is present (grade capped
// below band).
func aiMcpCapResult() *model.Result {
	r := sampleResult()
	r.Score = 92
	r.Rating = "RED"
	r.ScoringModel = "v2"
	r.SubScores = []model.GroupScore{
		{Group: model.GroupExposure, Score: 95, NotAssessed: 0},
		{Group: model.GroupAIAgent, Score: 20, NotAssessed: 0},
		{Group: model.GroupMCP, Score: 0, NotAssessed: 1},
	}
	r.CapDriver = &model.CapDriver{
		CheckID: "AGT002",
		Title:   "Lethal-trifecta agent: private data + untrusted ingest + exfil channel",
		Reason:  "dangerous AI agent / MCP capability",
		Grade:   "RED",
	}
	r.NotAssessed = []model.Finding{
		{
			CheckID: "MCP007",
			Title:   "MCP tool-poisoning drift (active probe)",
			Status:  model.StatusNotAssessed,
		},
	}
	return r
}

func TestTerminal_autonomyCap_aiMcpSubScores(t *testing.T) {
	var buf bytes.Buffer
	r := aiMcpCapResult()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "AI Agent Posture") {
		t.Errorf("expected 'AI Agent Posture' sub-score group in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "MCP Posture") {
		t.Errorf("expected 'MCP Posture' sub-score group in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "20/100") {
		t.Errorf("expected AI Agent Posture sub-score 20/100 in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "(1 not assessed)") {
		t.Errorf("expected '(1 not assessed)' on MCP Posture line; got:\n%s", out)
	}
	wantCap := "CAP: AGT002 Lethal-trifecta agent: private data + untrusted ingest + exfil channel — dangerous AI agent / MCP capability (grade capped to RED)"
	if !strings.Contains(out, wantCap) {
		t.Errorf("expected autonomy cap line:\n  %q\ngot:\n%s", wantCap, out)
	}
}

func TestMarkdown_autonomyCap_aiMcpSubScores(t *testing.T) {
	var buf bytes.Buffer
	r := aiMcpCapResult()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "| AI Agent Posture | 20/100 | 0 |") {
		t.Errorf("expected AI Agent Posture row in scoring breakdown table; got:\n%s", out)
	}
	if !strings.Contains(out, "| MCP Posture | 0/100 | 1 |") {
		t.Errorf("expected MCP Posture row in scoring breakdown table; got:\n%s", out)
	}
	wantCap := "> **Grade cap:** `AGT002` Lethal-trifecta agent: private data + untrusted ingest + exfil channel — dangerous AI agent / MCP capability (capped to **RED**)"
	if !strings.Contains(out, wantCap) {
		t.Errorf("expected autonomy cap callout:\n  %q\ngot:\n%s", wantCap, out)
	}
	if !strings.Contains(out, "- **MCP tool-poisoning drift (active probe)** (`MCP007`)") {
		t.Errorf("expected MCP007 in not-assessed section; got:\n%s", out)
	}
}

// hostOSCapResult builds a Result whose SubScores include a "Host OS" group
// and whose CapDriver carries HST003 (SSH internet password+root — Fatal).
// The numeric score is GREEN (88) but the cap forces RED.
func hostOSCapResult() *model.Result {
	r := sampleResult()
	r.Score = 88
	r.Rating = "RED"
	r.ScoringModel = "v2"
	r.SubScores = []model.GroupScore{
		{Group: model.GroupHost, Score: 10, NotAssessed: 2},
		{Group: model.GroupExposure, Score: 95, NotAssessed: 0},
	}
	r.CapDriver = &model.CapDriver{
		CheckID: "HST003",
		Title:   "SSH accessible from internet with password auth and root login enabled",
		Reason:  "fatal host-OS capability: internet SSH with password+root",
		Grade:   "RED",
	}
	r.NotAssessed = []model.Finding{
		{
			CheckID: "HST010",
			Title:   "Pending security updates (not assessed: collection disabled)",
			Status:  model.StatusNotAssessed,
		},
	}
	return r
}

func TestTerminal_hostOS_subScoreAndCap(t *testing.T) {
	var buf bytes.Buffer
	r := hostOSCapResult()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Host OS") {
		t.Errorf("expected 'Host OS' sub-score group in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "10/100") {
		t.Errorf("expected 'Host OS' sub-score 10/100 in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "(2 not assessed)") {
		t.Errorf("expected '(2 not assessed)' on Host OS line; got:\n%s", out)
	}
	wantCap := "CAP: HST003 SSH accessible from internet with password auth and root login enabled — fatal host-OS capability: internet SSH with password+root (grade capped to RED)"
	if !strings.Contains(out, wantCap) {
		t.Errorf("expected HST003 cap line:\n  %q\ngot:\n%s", wantCap, out)
	}
}

func TestMarkdown_hostOS_subScoreAndCap(t *testing.T) {
	var buf bytes.Buffer
	r := hostOSCapResult()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "| Host OS | 10/100 | 2 |") {
		t.Errorf("expected Host OS sub-score row in scoring breakdown; got:\n%s", out)
	}
	wantCap := "> **Grade cap:** `HST003` SSH accessible from internet with password auth and root login enabled — fatal host-OS capability: internet SSH with password+root (capped to **RED**)"
	if !strings.Contains(out, wantCap) {
		t.Errorf("expected HST003 cap callout:\n  %q\ngot:\n%s", wantCap, out)
	}
	if !strings.Contains(out, "- **Pending security updates (not assessed: collection disabled)** (`HST010`)") {
		t.Errorf("expected HST010 in not-assessed section; got:\n%s", out)
	}
}

func TestJSON_v2_roundtrip(t *testing.T) {
	var buf bytes.Buffer
	r := v2Result()
	if err := report.JSON(&buf, r); err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}

	var decoded model.Result
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\noutput:\n%s", err, buf.String())
	}
	if decoded.ScoringModel != "v2" {
		t.Errorf("ScoringModel mismatch: got %q, want %q", decoded.ScoringModel, "v2")
	}
	if len(decoded.SubScores) != len(r.SubScores) {
		t.Fatalf("SubScores len mismatch: got %d, want %d", len(decoded.SubScores), len(r.SubScores))
	}
	if decoded.SubScores[0].Group != model.GroupExposure || decoded.SubScores[0].Score != 90 {
		t.Errorf("SubScores[0] mismatch: got %+v", decoded.SubScores[0])
	}
	if decoded.SubScores[1].NotAssessed != 1 {
		t.Errorf("SubScores[1].NotAssessed mismatch: got %d, want 1", decoded.SubScores[1].NotAssessed)
	}
	if decoded.CapDriver == nil {
		t.Fatalf("CapDriver lost in round-trip")
	}
	if decoded.CapDriver.CheckID != "EXP001" || decoded.CapDriver.Grade != "RED" {
		t.Errorf("CapDriver mismatch: got %+v", decoded.CapDriver)
	}
	if len(decoded.NotAssessed) != 1 || decoded.NotAssessed[0].CheckID != "PKG010" {
		t.Errorf("NotAssessed mismatch: got %+v", decoded.NotAssessed)
	}
	if decoded.NotAssessed[0].Status != model.StatusNotAssessed {
		t.Errorf("NotAssessed[0].Status mismatch: got %v, want StatusNotAssessed", decoded.NotAssessed[0].Status)
	}
}
