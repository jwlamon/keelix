package report_test

// FIX-9: NotAssessed double-render skip + HTML/PDF v2 scoring rollup.
//
// (a) NotAssessed findings must NOT appear in the fail-sections of any
//     renderer; they must appear only in the NotAssessed section.
// (b) HTML and PDF must render the v2 scoring rollup (SubScores, CapDriver,
//     NotAssessed list) mirroring markdownScoringRollup.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/report"
)

// notAssessedResult builds a *model.Result that places a StatusNotAssessed
// finding into r.Findings (as the engine does — engine.go populates both
// r.Findings and r.NotAssessed from the same findings slice). The finding has
// Passed=false and Severity=Critical, which is how catalog.Finding() +
// notAssessed() build them. A second real-fail finding is included so the
// fail-section renders at all (we can assert the NA finding isn't in it).
func notAssessedResult() *model.Result {
	realFail := model.Finding{
		CheckID:  "EXP001",
		Group:    model.GroupExposure,
		Title:    "PostgreSQL reachable from the internet",
		Severity: model.SeverityCritical,
		Detail:   "Datastores should not be reachable from the internet.",
	}
	naFinding := model.Finding{
		CheckID:  "PKG010",
		Group:    model.GroupHost,
		Title:    "Security updates pending",
		Severity: model.SeverityCritical,
		Passed:   false,
		Status:   model.StatusNotAssessed,
		Detail:   "inside-out collector data unavailable",
	}
	return &model.Result{
		Target:       "test-host",
		ScannedAt:    time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC),
		Score:        50,
		Rating:       "RED",
		ScoringModel: "v2",
		SubScores: []model.GroupScore{
			{Group: model.GroupExposure, Score: 50, NotAssessed: 1},
		},
		CapDriver: &model.CapDriver{
			CheckID: "EXP001",
			Title:   "PostgreSQL reachable from the internet",
			Reason:  "fatal internet-exposed datastore",
			Grade:   "RED",
		},
		Findings:    []model.Finding{realFail, naFinding},
		NotAssessed: []model.Finding{naFinding},
	}
}

// ─── (a) NotAssessed double-render skip ──────────────────────────────────────

func TestTerminal_notAssessed_notInFailSection(t *testing.T) {
	var buf bytes.Buffer
	r := notAssessedResult()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	out := buf.String()

	// The real fail finding must appear.
	if !strings.Contains(out, "PostgreSQL reachable from the internet") {
		t.Errorf("expected real fail finding in terminal output; got:\n%s", out)
	}
	// The NA finding must NOT appear in the main fail section (it should only
	// be listed in the "Not assessed" section at the bottom).
	// Check that "Security updates pending" only appears in the not-assessed
	// section, NOT as a CRITICAL fail entry (i.e., not preceded by a severity label).
	// The easiest invariant: "CRITICAL" label must not appear alongside "Security updates pending".
	// We split on the not-assessed section boundary and confirm the NA title
	// does not appear before it.
	parts := strings.SplitN(out, "Not assessed", 2)
	if len(parts) < 2 {
		t.Fatalf("expected 'Not assessed' section in terminal output; got:\n%s", out)
	}
	beforeNA := parts[0]
	if strings.Contains(beforeNA, "Security updates pending") {
		t.Errorf("NotAssessed finding 'Security updates pending' appeared in the fail section (before 'Not assessed'); it should only appear in the not-assessed section.\nOutput:\n%s", out)
	}
}

func TestMarkdown_notAssessed_notInFindingsSection(t *testing.T) {
	var buf bytes.Buffer
	r := notAssessedResult()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown: %v", err)
	}
	out := buf.String()

	// The real fail finding must appear.
	if !strings.Contains(out, "PostgreSQL reachable from the internet") {
		t.Errorf("expected real fail finding in markdown output; got:\n%s", out)
	}

	// The NA finding must NOT appear in the ## Findings section.
	// Split on "## Scoring Breakdown" (or "## Control") which comes after Findings.
	findingsSection := out
	if idx := strings.Index(out, "## Control-Coverage"); idx != -1 {
		findingsSection = out[:idx]
	}
	if strings.Contains(findingsSection, "Security updates pending") {
		// Allow it only in "### Not Assessed" (inside Scoring Breakdown section,
		// which may appear before Control-Coverage Matrix in the future, but
		// currently markdownScoringRollup is after Remediation Appendix).
		// For now: the finding must not appear before the Control-Coverage matrix.
		t.Errorf("NotAssessed finding appeared in the Findings section; it should be excluded.\nFindings section:\n%s", findingsSection)
	}
}

func TestHTML_notAssessed_notInFindingsSection(t *testing.T) {
	var buf bytes.Buffer
	r := notAssessedResult()
	if err := report.HTML(&buf, r); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()

	// The real fail finding must appear.
	if !strings.Contains(out, "PostgreSQL reachable from the internet") {
		t.Errorf("expected real fail finding in HTML output; got:\n%s", out)
	}

	// The NA finding must NOT appear in the Findings section.
	// Split on the Control-Coverage Matrix heading to get just the findings section.
	findingsSection := out
	if idx := strings.Index(out, "<h2>Control-Coverage Matrix</h2>"); idx != -1 {
		findingsSection = out[:idx]
	}
	if strings.Contains(findingsSection, "Security updates pending") {
		t.Errorf("NotAssessed finding appeared in the HTML Findings section; it should be excluded.\nFindings section:\n%s", findingsSection)
	}
}

func TestPDF_notAssessed_noPanic(t *testing.T) {
	// PDF cannot be inspected as text, but must not panic / error when a
	// NotAssessed finding is in r.Findings.
	var buf bytes.Buffer
	r := notAssessedResult()
	if err := report.PDF(&buf, r); err != nil {
		t.Fatalf("PDF returned error with NotAssessed finding: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("PDF output is empty")
	}
}

// ─── (b) HTML/PDF v2 scoring rollup ──────────────────────────────────────────

func TestHTML_v2_scoringRollup(t *testing.T) {
	var buf bytes.Buffer
	r := notAssessedResult()
	if err := report.HTML(&buf, r); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "Scoring Breakdown") {
		t.Errorf("HTML output missing 'Scoring Breakdown' section; got:\n%s", out)
	}
	if !strings.Contains(out, "Network Exposure") {
		t.Errorf("HTML output missing 'Network Exposure' sub-score group; got:\n%s", out)
	}
	if !strings.Contains(out, "50/100") {
		t.Errorf("HTML output missing '50/100' sub-score; got:\n%s", out)
	}
	if !strings.Contains(out, "Grade cap") || !strings.Contains(out, "EXP001") {
		t.Errorf("HTML output missing CapDriver section; got:\n%s", out)
	}
	if !strings.Contains(out, "Security updates pending") {
		t.Errorf("HTML output missing NotAssessed item 'Security updates pending' in rollup; got:\n%s", out)
	}
}

func TestPDF_v2_scoringRollup_nonEmpty(t *testing.T) {
	// PDF scoring rollup cannot be inspected as text; verify the document
	// is produced without error and is non-empty (functional smoke test).
	var buf bytes.Buffer
	r := notAssessedResult()
	if err := report.PDF(&buf, r); err != nil {
		t.Fatalf("PDF returned error with v2 scoring data: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("PDF output is empty")
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Errorf("PDF output does not start with %%PDF")
	}
}
