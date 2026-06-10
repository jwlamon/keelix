package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jakelamon/keelix/internal/model"
	"github.com/jakelamon/keelix/internal/report"
)

// sampleResult constructs a minimal *model.Result with 1 critical, 1 warning,
// 1 passed finding, score 41, rating "RED" for use across all tests.
func sampleResult() *model.Result {
	critical := model.Finding{
		CheckID:  "EXP001",
		Group:    model.GroupExposure,
		Title:    "PostgreSQL reachable from the internet (port 5432)",
		Severity: model.SeverityCritical,
		Service:  "db",
		Resource: "port 5432",
		Detail:   "Datastores should not be reachable from the internet.",
		Evidence: "TCP connect to 203.0.113.1:5432 succeeded",
		Fix: model.Fix{
			Summary:  "Bind the port to 127.0.0.1 and add a DOCKER-USER iptables rule.",
			Diff:     "-    ports:\n-      - \"5432:5432\"\n+    ports:\n+      - \"127.0.0.1:5432:5432\"",
			Commands: []string{"iptables -I DOCKER-USER -p tcp --dport 5432 -j DROP"},
		},
		Controls: []model.ControlRef{
			{Framework: "SOC2", ID: "CC6.6", Title: "Boundary protection / external threats"},
			{Framework: "ISO27001", ID: "A.8.20", Title: "Network security"},
			{Framework: "CIS-Docker", ID: "5.7", Title: "Privileged ports / unnecessary exposure"},
		},
	}

	warning := model.Finding{
		CheckID:  "FW002",
		Group:    model.GroupFirewall,
		Title:    "Sensitive port bound to all interfaces (0.0.0.0)",
		Severity: model.SeverityWarning,
		Service:  "cache",
		Resource: "port 6379",
		Detail:   "Redis port is bound to 0.0.0.0 instead of 127.0.0.1.",
		Evidence: "ports: \"6379:6379\" with no bind address",
		Fix: model.Fix{
			Summary: "Change the port binding to include a localhost address.",
		},
		Controls: []model.ControlRef{
			{Framework: "SOC2", ID: "CC6.6", Title: "Boundary protection / external threats"},
			{Framework: "ISO27001", ID: "A.8.20", Title: "Network security"},
		},
	}

	passed := model.Finding{
		CheckID:  "TLS002",
		Group:    model.GroupTLS,
		Title:    "TLS certificate is valid",
		Severity: model.SeverityOK,
		Passed:   true,
		Detail:   "Certificate expires in 87 days.",
		Controls: []model.ControlRef{
			{Framework: "SOC2", ID: "CC6.7", Title: "Data in transit encryption"},
		},
	}

	return &model.Result{
		Target:    "example.com",
		ScannedAt: time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		Version:   "0.1.0",
		Score:     41,
		Rating:    "RED",
		Counts: model.Counts{
			Critical: 1,
			Warning:  1,
			Passed:   1,
		},
		Findings: []model.Finding{critical, warning, passed},
	}
}

// ─── Terminal ────────────────────────────────────────────────────────────────

func TestTerminal_plain(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "41/100") {
		t.Errorf("expected '41/100' in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected 'CRITICAL' in terminal output; got:\n%s", out)
	}
	if !strings.Contains(out, "Maps to:") {
		t.Errorf("expected 'Maps to:' in terminal output; got:\n%s", out)
	}
}

func TestTerminal_noANSI_when_color_false(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("expected no ANSI codes when color=false")
	}
}

func TestTerminal_color_enabled(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Terminal(&buf, r, true); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	// ANSI codes should appear somewhere
	if !strings.Contains(buf.String(), "\033[") {
		t.Errorf("expected ANSI codes when color=true")
	}
}

// ─── JSON ────────────────────────────────────────────────────────────────────

func TestJSON_roundtrip(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.JSON(&buf, r); err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}

	var decoded model.Result
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v\noutput:\n%s", err, buf.String())
	}
	if decoded.Score != r.Score {
		t.Errorf("Score mismatch: got %d, want %d", decoded.Score, r.Score)
	}
	if decoded.Rating != r.Rating {
		t.Errorf("Rating mismatch: got %s, want %s", decoded.Rating, r.Rating)
	}
	if len(decoded.Findings) != len(r.Findings) {
		t.Errorf("Findings count mismatch: got %d, want %d", len(decoded.Findings), len(r.Findings))
	}
}

// ─── Markdown ────────────────────────────────────────────────────────────────

func TestMarkdown_sections(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	out := buf.String()

	sections := []string{
		"# Keelix Security Posture Report",
		"## Executive Summary",
		"## Findings",
		"## Control-Coverage Matrix",
		"## Remediation Appendix",
		"## Methodology & Scope",
	}
	for _, sec := range sections {
		if !strings.Contains(out, sec) {
			t.Errorf("expected section %q in Markdown output", sec)
		}
	}
}

func TestMarkdown_failRow(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "| FAIL |") {
		t.Errorf("expected '| FAIL |' row in control-coverage matrix")
	}
}

func TestMarkdown_score(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "41/100") {
		t.Errorf("expected '41/100' in Markdown output")
	}
}

// ─── HTML ────────────────────────────────────────────────────────────────────

func TestHTML_hasTable(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.HTML(&buf, r); err != nil {
		t.Fatalf("HTML returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "<table") {
		t.Errorf("expected '<table' in HTML output")
	}
}

func TestHTML_escapesScript(t *testing.T) {
	r := sampleResult()
	// Inject a script tag into a finding title
	r.Findings[0].Title = "<script>alert('xss')</script>"

	var buf bytes.Buffer
	if err := report.HTML(&buf, r); err != nil {
		t.Fatalf("HTML returned error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") {
		t.Errorf("HTML output contains unescaped <script> tag — XSS risk")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped &lt;script&gt; in HTML output")
	}
}

// ─── PDF ─────────────────────────────────────────────────────────────────────

func TestPDF_nonEmpty(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.PDF(&buf, r); err != nil {
		t.Fatalf("PDF returned error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("PDF output is empty")
	}
}

func TestPDF_startWithPDFMagic(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.PDF(&buf, r); err != nil {
		t.Fatalf("PDF returned error: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF")) {
		t.Errorf("PDF output does not start with %%PDF; starts with: %q", buf.Bytes()[:min(buf.Len(), 8)])
	}
}

// ─── CoverageMatrix ───────────────────────────────────────────────────────────

func TestCoverageMatrix_failOnCritical(t *testing.T) {
	r := sampleResult()
	rows := report.CoverageMatrix(r)

	// CC6.6 is mapped by both the critical and warning finding — must be FAIL
	found := false
	for _, row := range rows {
		if row.Framework == "SOC2" && row.Control == "CC6.6" {
			found = true
			if row.Status != "FAIL" {
				t.Errorf("expected SOC2 CC6.6 to be FAIL, got %s", row.Status)
			}
		}
	}
	if !found {
		t.Errorf("SOC2 CC6.6 not found in coverage matrix")
	}
}

func TestCoverageMatrix_passOnOKOnly(t *testing.T) {
	r := sampleResult()
	rows := report.CoverageMatrix(r)

	// CC6.7 is only referenced by the passing TLS finding — must be PASS
	found := false
	for _, row := range rows {
		if row.Framework == "SOC2" && row.Control == "CC6.7" {
			found = true
			if row.Status != "PASS" {
				t.Errorf("expected SOC2 CC6.7 to be PASS, got %s", row.Status)
			}
		}
	}
	if !found {
		t.Errorf("SOC2 CC6.7 not found in coverage matrix")
	}
}

func TestCoverageMatrix_testedTrue(t *testing.T) {
	r := sampleResult()
	for _, row := range report.CoverageMatrix(r) {
		if !row.Tested {
			t.Errorf("all controls in sample result should be Tested=true; got Tested=false for %s %s",
				row.Framework, row.Control)
		}
	}
}

// TestCoverageMatrix_notAssessedDoesNotFail asserts that a StatusNotAssessed
// critical finding referencing a control marks it as tested/covered but does
// NOT flip it to FAIL (R2-6 fix).
func TestCoverageMatrix_notAssessedDoesNotFail(t *testing.T) {
	naFinding := model.Finding{
		CheckID:  "HRD999",
		Group:    model.GroupHost,
		Title:    "Not-assessed critical check",
		Severity: model.SeverityCritical,
		Passed:   false,
		Status:   model.StatusNotAssessed,
		Controls: []model.ControlRef{
			{Framework: "SOC2", ID: "CC8.1", Title: "Change management"},
		},
	}
	r := &model.Result{
		Target:   "test-host",
		Findings: []model.Finding{naFinding},
	}
	rows := report.CoverageMatrix(r)

	var found bool
	for _, row := range rows {
		if row.Framework == "SOC2" && row.Control == "CC8.1" {
			found = true
			if row.Status != "PASS" {
				t.Errorf("R2-6: NotAssessed finding must not flip control to FAIL; got Status=%s", row.Status)
			}
			if !row.Tested {
				t.Errorf("R2-6: control referenced by NotAssessed finding should still be Tested=true")
			}
		}
	}
	if !found {
		t.Errorf("SOC2 CC8.1 not found in coverage matrix — NotAssessed finding controls should still be counted")
	}
}

// min is a small helper so we don't import slices.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─── Branding ─────────────────────────────────────────────────────────────────

func TestMarkdown_defaultBrand(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	// BrandName is empty — must default to "Keelix"
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Keelix") {
		t.Errorf("expected 'Keelix' in Markdown output when BrandName is empty")
	}
}

func TestMarkdown_customBrand(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	r.BrandName = "AcmeSec"
	if err := report.Markdown(&buf, r); err != nil {
		t.Fatalf("Markdown returned error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "AcmeSec") {
		t.Errorf("expected 'AcmeSec' in Markdown output, got:\n%s", out)
	}
	if strings.Contains(out, "# Keelix") && !strings.Contains(out, "AcmeSec") {
		t.Errorf("expected branded title to say 'AcmeSec', but it didn't")
	}
}

func TestTerminal_defaultBrand(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "Keelix") {
		t.Errorf("expected 'Keelix' in terminal output when BrandName is empty")
	}
}

func TestTerminal_customBrand(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	r.BrandName = "AcmeSec"
	if err := report.Terminal(&buf, r, false); err != nil {
		t.Fatalf("Terminal returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "AcmeSec") {
		t.Errorf("expected 'AcmeSec' in terminal output when BrandName is set")
	}
}

// ─── QF-2: AI/MCP section gating ─────────────────────────────────────────────

// TestAIMCPSection_absent_whenNoCollectorNoAIMCPFindings asserts that Terminal,
// Markdown, and HTML do NOT emit "AI / MCP Posture" when Collector is nil and
// no findings belong to GroupAIAgent or GroupMCP (compose-only scan).
func TestAIMCPSection_absent_whenNoCollectorNoAIMCPFindings(t *testing.T) {
	r := sampleResult() // Collector is nil; findings are GroupExposure/GroupFirewall/GroupTLS
	if r.Collector != nil {
		t.Fatal("sampleResult must have nil Collector for this test")
	}

	t.Run("Terminal", func(t *testing.T) {
		var buf bytes.Buffer
		if err := report.Terminal(&buf, r, false); err != nil {
			t.Fatalf("Terminal error: %v", err)
		}
		if strings.Contains(buf.String(), "AI / MCP Posture") {
			t.Errorf("Terminal must not emit 'AI / MCP Posture' when Collector==nil and no AI/MCP findings")
		}
	})

	t.Run("Markdown", func(t *testing.T) {
		var buf bytes.Buffer
		if err := report.Markdown(&buf, r); err != nil {
			t.Fatalf("Markdown error: %v", err)
		}
		if strings.Contains(buf.String(), "## AI / MCP Posture") {
			t.Errorf("Markdown must not emit '## AI / MCP Posture' when Collector==nil and no AI/MCP findings")
		}
	})

	t.Run("HTML", func(t *testing.T) {
		var buf bytes.Buffer
		if err := report.HTML(&buf, r); err != nil {
			t.Fatalf("HTML error: %v", err)
		}
		if strings.Contains(buf.String(), "AI / MCP Posture") {
			t.Errorf("HTML must not emit 'AI / MCP Posture' when Collector==nil and no AI/MCP findings")
		}
	})
}

// TestAIMCPSection_present_whenCollectorSet asserts that the AI/MCP section IS
// emitted when Collector is non-nil (inside-out collection ran), even if there
// are no explicit AI/MCP findings.
func TestAIMCPSection_present_whenCollectorSet(t *testing.T) {
	r := sampleResult()
	r.Collector = &model.Signals{} // simulate collection having run

	t.Run("Markdown", func(t *testing.T) {
		var buf bytes.Buffer
		if err := report.Markdown(&buf, r); err != nil {
			t.Fatalf("Markdown error: %v", err)
		}
		if !strings.Contains(buf.String(), "## AI / MCP Posture") {
			t.Errorf("Markdown must emit '## AI / MCP Posture' when Collector is non-nil")
		}
	})

	t.Run("HTML", func(t *testing.T) {
		var buf bytes.Buffer
		if err := report.HTML(&buf, r); err != nil {
			t.Fatalf("HTML error: %v", err)
		}
		if !strings.Contains(buf.String(), "AI / MCP Posture") {
			t.Errorf("HTML must emit 'AI / MCP Posture' when Collector is non-nil")
		}
	})
}

// TestAIMCPSection_present_whenAIMCPFinding asserts that the AI/MCP section IS
// emitted when at least one finding belongs to GroupAIAgent or GroupMCP.
func TestAIMCPSection_present_whenAIMCPFinding(t *testing.T) {
	r := sampleResult()
	r.Findings = append(r.Findings, model.Finding{
		CheckID:  "AGT001",
		Group:    model.GroupAIAgent,
		Title:    "AI agent with unattended autonomy",
		Severity: model.SeverityCritical,
		Status:   model.StatusNotAssessed,
	})

	t.Run("Markdown", func(t *testing.T) {
		var buf bytes.Buffer
		if err := report.Markdown(&buf, r); err != nil {
			t.Fatalf("Markdown error: %v", err)
		}
		if !strings.Contains(buf.String(), "## AI / MCP Posture") {
			t.Errorf("Markdown must emit '## AI / MCP Posture' when an AI/MCP finding is present")
		}
	})
}
