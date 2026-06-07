package report

import (
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestMarkdown_HasAIMcpSection(t *testing.T) {
	r := res([]model.GroupScore{{Group: model.GroupMCP, Score: 50}}, []model.Finding{{CheckID: "MCP001", Group: model.GroupMCP, Passed: false, Status: model.StatusAssessed}}, nil)
	var sb strings.Builder
	if err := Markdown(&sb, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), "AI / MCP Posture") {
		t.Errorf("markdown missing AI/MCP section:\n%s", sb.String())
	}
}

func res(subs []model.GroupScore, fs []model.Finding, cap *model.CapDriver) *model.Result {
	return &model.Result{SubScores: subs, Findings: fs, CapDriver: cap}
}

func TestAIMcpPanel_TrifectaCapsRed(t *testing.T) {
	r := res(
		[]model.GroupScore{{Group: model.GroupAIAgent, Score: 10}, {Group: model.GroupMCP, Score: 80}},
		[]model.Finding{{CheckID: "AGT002", Group: model.GroupAIAgent, Title: "Lethal-trifecta capability co-presence", Severity: model.SeverityCritical, Status: model.StatusAssessed}},
		&model.CapDriver{CheckID: "AGT002", Grade: "RED", Reason: "lethal trifecta"},
	)
	out := aiMcpPanel(r)
	if !strings.Contains(out, "AI / MCP Posture") {
		t.Errorf("panel missing header:\n%s", out)
	}
	if !strings.Contains(out, "trifecta") {
		t.Errorf("panel must surface the lethal-trifecta:\n%s", out)
	}
	if !strings.Contains(strings.ToUpper(out), "RED") {
		t.Errorf("panel must say AI/MCP capped the box RED:\n%s", out)
	}
}

func TestAIMcpPanel_NoneDetected(t *testing.T) {
	// No AGT/MCP findings at all → "nothing to assess" clean state, not blank.
	r := res(nil, []model.Finding{{CheckID: "EXP001", Group: model.GroupExposure}}, nil)
	out := aiMcpPanel(r)
	if !strings.Contains(strings.ToLower(out), "no ai agents or mcp") {
		t.Errorf("expected a 'none detected' line, got:\n%s", out)
	}
}

func TestAIMcpPanel_NotAssessedIsHonest(t *testing.T) {
	// AGT findings exist but are NotAssessed (no signals) → must NOT read as clean pass.
	r := res(
		[]model.GroupScore{{Group: model.GroupAIAgent, Score: 100, NotAssessed: 3}},
		[]model.Finding{{CheckID: "AGT001", Group: model.GroupAIAgent, Status: model.StatusNotAssessed}},
		nil,
	)
	out := aiMcpPanel(r)
	if strings.Contains(strings.ToLower(out), "no issues") {
		t.Errorf("must not claim a clean pass when checks were not assessed:\n%s", out)
	}
	if !strings.Contains(strings.ToLower(out), "not assessed") {
		t.Errorf("must disclose not-assessed state:\n%s", out)
	}
}

func TestTerminal_RendersAIMcpPanelAfterHeader(t *testing.T) {
	r := res(
		[]model.GroupScore{{Group: model.GroupAIAgent, Score: 10}},
		[]model.Finding{{CheckID: "AGT002", Group: model.GroupAIAgent, Title: "trifecta", Severity: model.SeverityCritical, Status: model.StatusAssessed}},
		&model.CapDriver{CheckID: "AGT002", Grade: "RED", Reason: "x"},
	)
	r.Score = 0
	r.Rating = "RED"
	var sb strings.Builder
	if err := Terminal(&sb, r, false); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	hdr := strings.Index(out, "Posture Score")
	panel := strings.Index(out, "AI / MCP Posture")
	if panel < 0 || hdr < 0 || panel < hdr {
		t.Errorf("AI/MCP panel must render after the score header; hdr=%d panel=%d\n%s", hdr, panel, out)
	}
}
