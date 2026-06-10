package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jakelamon/keelix/internal/model"
	"github.com/jakelamon/keelix/internal/report"
)

// buildServiceSubScoreResult returns a minimal *model.Result that contains
// a GroupService sub-score so we can verify the renderer outputs it.
func buildServiceSubScoreResult() *model.Result {
	return &model.Result{
		Target:       "test-host",
		ScannedAt:    time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC),
		Score:        72,
		Rating:       "YELLOW",
		ScoringModel: "v2",
		SubScores: []model.GroupScore{
			{Group: model.GroupExposure, Score: 90, NotAssessed: 0},
			{Group: model.GroupService, Score: 45, NotAssessed: 3},
		},
		Findings: []model.Finding{
			{
				CheckID:  "SVC001",
				Group:    model.GroupService,
				Title:    "Redis accessible without authentication",
				Severity: model.SeverityCritical,
				Detail:   "test",
				Controls: []model.ControlRef{{Framework: "SOC2", ID: "CC6.1"}},
			},
		},
	}
}

func TestTerminalRender_ServiceSubScore(t *testing.T) {
	r := buildServiceSubScoreResult()
	var buf bytes.Buffer
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Service Configuration") {
		t.Errorf("Terminal output does not contain GroupService sub-score label; got:\n%s", out)
	}
	if !strings.Contains(out, "45/100") {
		t.Errorf("Terminal output does not contain service sub-score 45/100; got:\n%s", out)
	}
	if !strings.Contains(out, "(3 not assessed)") {
		t.Errorf("Terminal output does not contain not-assessed count; got:\n%s", out)
	}
}

func TestMarkdownRender_ServiceSubScore(t *testing.T) {
	r := buildServiceSubScoreResult()
	var buf bytes.Buffer
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Service Configuration") {
		t.Errorf("Markdown output does not contain GroupService sub-score label; got:\n%s", out)
	}
	if !strings.Contains(out, "45/100") {
		t.Errorf("Markdown output does not contain service sub-score 45/100; got:\n%s", out)
	}
}
