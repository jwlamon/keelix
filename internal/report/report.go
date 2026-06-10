// Package report renders a *model.Result into five formats: Terminal, JSON,
// Markdown, HTML, and PDF. All renderers are deterministic and produce
// audit-grade output.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
	"github.com/jakelamon/keelix/internal/threatfeed"
)

// ─── Brand helper ────────────────────────────────────────────────────────────

// brandName returns the configured product name, falling back to "Keelix".
func brandName(r *model.Result) string {
	if r.BrandName != "" {
		return r.BrandName
	}
	return "Keelix"
}

// threatDataNote returns a one-line staleness banner and a methodology sentence
// describing the embedded threat-feed snapshot, using the injected scan time as
// "now" (no wall-clock read in render). banner is empty when the data is fresh.
func threatDataNote(now time.Time) (banner, methodology string) {
	snap := threatfeed.SnapshotDate()
	methodology = fmt.Sprintf(
		"Exploitability weighting uses an embedded CISA KEV + FIRST.org EPSS snapshot dated %s.",
		snap.Format("2006-01-02"))
	if threatfeed.IsStale(now) {
		days := int(now.UTC().Sub(snap).Hours() / 24)
		banner = fmt.Sprintf("threat data is %d days old; KEV/EPSS may understate current risk", days)
	}
	return banner, methodology
}

// ─── ANSI helpers ────────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiBold   = "\033[1m"
)

func colorize(s, code string, enabled bool) string {
	if !enabled {
		return s
	}
	return code + s + ansiReset
}

// ─── Finding sort order ───────────────────────────────────────────────────────

// sortedFindings returns findings in display order: Critical → Warning → Info → OK,
// then by CheckID within each group.
func sortedFindings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := out[i].Severity, out[j].Severity
		// descending severity
		if si != sj {
			return si > sj
		}
		return out[i].CheckID < out[j].CheckID
	})
	return out
}

// hasAIMCPContent returns true when the report should include an AI / MCP
// Posture section: either inside-out collection ran (Collector != nil) or
// at least one finding belongs to an AI Agent / MCP check group.
func hasAIMCPContent(r *model.Result) bool {
	if r.Collector != nil {
		return true
	}
	for i := range r.Findings {
		g := r.Findings[i].Group
		if g == model.GroupAIAgent || g == model.GroupMCP {
			return true
		}
	}
	return false
}

// ─── Terminal ────────────────────────────────────────────────────────────────

// Terminal writes a human-readable ANSI report to w.
// When color is false the output is plain text (CI-safe).
func Terminal(w io.Writer, r *model.Result, color bool) error {
	rating := r.Rating
	var scoreColor string
	switch rating {
	case "RED":
		scoreColor = ansiRed
	case "YELLOW":
		scoreColor = ansiYellow
	default:
		scoreColor = ansiGreen
	}

	header := fmt.Sprintf("%s   Posture Score: %d/100  [%s]", brandName(r), r.Score, rating)
	_, err := fmt.Fprintln(w, colorize(header, ansiBold, color)+"\n")
	if err != nil {
		return err
	}
	_ = scoreColor // used via rating label coloring below

	if hasAIMCPContent(r) {
		if _, err := fmt.Fprintln(w, colorize(strings.TrimRight(aiMcpPanel(r), "\n"), ansiBold, color)+"\n"); err != nil {
			return err
		}
	}

	sorted := sortedFindings(r.Findings)
	for _, f := range sorted {
		if f.Passed || f.Severity == model.SeverityOK || f.Status == model.StatusNotAssessed {
			continue // only show failures; not-assessed findings render in the rollup section only
		}
		var sev string
		var sevColor string
		switch f.Severity {
		case model.SeverityCritical:
			sev = "CRITICAL"
			sevColor = ansiRed
		case model.SeverityWarning:
			sev = "WARNING"
			sevColor = ansiYellow
		default:
			sev = "INFO"
			sevColor = ansiGreen
		}

		sevLabel := colorize(sev, sevColor, color)
		title := fmt.Sprintf("  %s  %s  %s  [%s]", f.Severity.Emoji(), sevLabel, f.Title, f.CheckID)
		if _, err := fmt.Fprintln(w, title); err != nil {
			return err
		}

		detail := f.Detail
		if f.AIExplanation != "" {
			detail = f.AIExplanation
		}
		if detail != "" {
			if _, err := fmt.Fprintf(w, "     %s\n", detail); err != nil {
				return err
			}
		}
		if f.Evidence != "" {
			if _, err := fmt.Fprintf(w, "     Evidence: %s\n", f.Evidence); err != nil {
				return err
			}
		}

		// Fix block
		if f.Fix.Summary != "" || f.Fix.Diff != "" || len(f.Fix.Commands) > 0 {
			if _, err := fmt.Fprintf(w, "     FIX: %s\n", f.Fix.Summary); err != nil {
				return err
			}
			if f.Fix.Diff != "" {
				for _, line := range strings.Split(f.Fix.Diff, "\n") {
					if _, err := fmt.Fprintf(w, "          %s\n", line); err != nil {
						return err
					}
				}
			}
			for _, cmd := range f.Fix.Commands {
				if _, err := fmt.Fprintf(w, "          $ %s\n", cmd); err != nil {
					return err
				}
			}
		}

		// Controls
		if len(f.Controls) > 0 {
			refs := make([]string, len(f.Controls))
			for i, c := range f.Controls {
				refs[i] = c.Framework + " " + c.ID
			}
			if _, err := fmt.Fprintf(w, "     Maps to: %s\n", strings.Join(refs, ", ")); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}

	// Summary line
	summary := fmt.Sprintf("  %d critical, %d warnings, %d passed.",
		r.Counts.Critical, r.Counts.Warning, r.Counts.Passed)
	if _, err := fmt.Fprintln(w, summary); err != nil {
		return err
	}

	if err := terminalScoringRollup(w, r, color); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "  Guided fix:  keelix fix --interactive"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  Evidence:    keelix report --format pdf"); err != nil {
		return err
	}
	return nil
}

// terminalScoringRollup renders the v2 scoring model line, per-group sub-scores,
// a prominent CAP line (only when a cap lowered the grade), and the not-assessed
// section. It is a no-op for v1 results (empty ScoringModel) so existing output
// is unchanged.
func terminalScoringRollup(w io.Writer, r *model.Result, color bool) error {
	if r.ScoringModel == "" {
		return nil
	}
	if _, err := fmt.Fprintf(w, "\n  Scoring model: %s\n", r.ScoringModel); err != nil {
		return err
	}
	if banner, _ := threatDataNote(r.ScannedAt); banner != "" {
		if _, err := fmt.Fprintf(w, "  ⚠ %s\n", banner); err != nil {
			return err
		}
	}
	for _, gs := range r.SubScores {
		line := fmt.Sprintf("    %-28s %d/100", string(gs.Group), gs.Score)
		if gs.NotAssessed > 0 {
			line += fmt.Sprintf("  (%d not assessed)", gs.NotAssessed)
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	if r.CapDriver != nil {
		cap := fmt.Sprintf("  CAP: %s %s — %s (grade capped to %s)",
			r.CapDriver.CheckID, r.CapDriver.Title, r.CapDriver.Reason, r.CapDriver.Grade)
		if _, err := fmt.Fprintln(w, colorize(cap, ansiBold+ansiRed, color)); err != nil {
			return err
		}
	}
	if len(r.NotAssessed) > 0 {
		if _, err := fmt.Fprintf(w, "  Not assessed (%d):\n", len(r.NotAssessed)); err != nil {
			return err
		}
		for _, f := range r.NotAssessed {
			if _, err := fmt.Fprintf(w, "    - %s [%s]\n", f.Title, f.CheckID); err != nil {
				return err
			}
		}
	}
	if _, m := threatDataNote(r.ScannedAt); m != "" {
		if _, err := fmt.Fprintf(w, "  Threat data: %s\n", m); err != nil {
			return err
		}
	}
	return nil
}

// ─── JSON ────────────────────────────────────────────────────────────────────

// JSON writes the Result as indented JSON.
func JSON(w io.Writer, r *model.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ─── Coverage matrix ─────────────────────────────────────────────────────────

// MatrixRow represents one row in the control-coverage matrix.
type MatrixRow struct {
	Framework string
	Control   string
	Title     string
	Tested    bool
	Status    string // "PASS" or "FAIL"
}

// CoverageMatrix aggregates all control references from r.Findings into a
// deduplicated, sorted matrix. A control is FAIL if any failing finding
// (Warning or Critical) maps to it; otherwise PASS.
func CoverageMatrix(r *model.Result) []MatrixRow {
	type key struct{ fw, id string }
	type entry struct {
		title  string
		tested bool
		fail   bool
	}
	m := map[key]*entry{}

	for _, f := range r.Findings {
		for _, c := range f.Controls {
			k := key{c.Framework, c.ID}
			e, ok := m[k]
			if !ok {
				e = &entry{title: c.Title}
				m[k] = e
			}
			e.tested = true
			if c.Title != "" && e.title == "" {
				e.title = c.Title
			}
			// NotAssessed findings mark the control as covered/tested but must
			// not flip its status to FAIL — the check could not run, so we have
			// no evidence of a real failure (R2-6).
			if f.IsFail() && f.Status != model.StatusNotAssessed {
				e.fail = true
			}
		}
	}

	rows := make([]MatrixRow, 0, len(m))
	for k, e := range m {
		status := "PASS"
		if e.fail {
			status = "FAIL"
		}
		rows = append(rows, MatrixRow{
			Framework: k.fw,
			Control:   k.id,
			Title:     e.title,
			Tested:    e.tested,
			Status:    status,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Framework != rows[j].Framework {
			return rows[i].Framework < rows[j].Framework
		}
		return rows[i].Control < rows[j].Control
	})

	return rows
}

// ─── Markdown ────────────────────────────────────────────────────────────────

// Markdown writes the full Security Posture Report as a Markdown document.
func Markdown(w io.Writer, r *model.Result) error {
	wf := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}

	// 1. Cover
	if err := wf("# %s Security Posture Report\n\n", brandName(r)); err != nil {
		return err
	}
	if err := wf("| Field | Value |\n|---|---|\n"); err != nil {
		return err
	}
	if err := wf("| **Target** | %s |\n", r.Target); err != nil {
		return err
	}
	if err := wf("| **Scan Timestamp** | %s |\n", r.ScannedAt.UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := wf("| **Posture Score** | %d/100 (%s) |\n", r.Score, r.Rating); err != nil {
		return err
	}
	if err := wf("| **Scanner Version** | %s |\n", r.Version); err != nil {
		return err
	}
	if err := wf("| **Catalog Version** | %s |\n\n", catalog.CatalogVersion); err != nil {
		return err
	}

	// 2. Executive Summary
	if err := wf("## Executive Summary\n\n"); err != nil {
		return err
	}
	summary := r.AISummary
	if summary == "" {
		summary = fmt.Sprintf(
			"%s assessed %s and assigned a posture score of %d/100 (%s). "+
				"It identified %d critical and %d warning findings, with %d checks passing.",
			brandName(r), r.Target, r.Score, r.Rating, r.Counts.Critical, r.Counts.Warning, r.Counts.Passed,
		)
	}
	if err := wf("%s\n\n", summary); err != nil {
		return err
	}

	// 3. AI / MCP Posture panel — only when collection ran or AI/MCP findings exist.
	if hasAIMCPContent(r) {
		if err := wf("## AI / MCP Posture\n\n"); err != nil {
			return err
		}
		panelLines := strings.SplitAfter(aiMcpPanel(r), "\n")
		// panelLines[0] is "AI / MCP Posture\n" — skip it, emit the body lines.
		for _, line := range panelLines[1:] {
			if line == "" {
				continue
			}
			if err := wf("%s\n", strings.TrimRight(line, "\n")); err != nil {
				return err
			}
		}
		if err := wf("\n"); err != nil {
			return err
		}
	}

	// 4. Findings
	if err := wf("## Findings\n\n"); err != nil {
		return err
	}
	sorted := sortedFindings(r.Findings)
	lastSev := model.Severity(-1)
	for _, f := range sorted {
		if f.Passed || f.Severity == model.SeverityOK || f.Status == model.StatusNotAssessed {
			continue // not-assessed findings appear only in the scoring rollup section
		}
		if f.Severity != lastSev {
			if err := wf("### %s Findings\n\n", f.Severity.Label()); err != nil {
				return err
			}
			lastSev = f.Severity
		}

		service := f.Service
		if service == "" {
			service = f.Resource
		}
		if service == "" {
			service = "—"
		}

		detail := f.Detail
		if f.AIExplanation != "" {
			detail = f.AIExplanation
		}

		if err := wf("#### %s %s — [%s]\n\n", f.Severity.Emoji(), f.Title, f.CheckID); err != nil {
			return err
		}
		if err := wf("**Service/Resource:** %s\n\n", service); err != nil {
			return err
		}
		if detail != "" {
			if err := wf("%s\n\n", detail); err != nil {
				return err
			}
		}
		if f.Evidence != "" {
			if err := wf("**Evidence:** %s\n\n", f.Evidence); err != nil {
				return err
			}
		}
		if f.Fix.Summary != "" {
			if err := wf("**Fix:** %s\n\n", f.Fix.Summary); err != nil {
				return err
			}
		}
		if f.Fix.Diff != "" {
			if err := wf("```diff\n%s\n```\n\n", f.Fix.Diff); err != nil {
				return err
			}
		}
		if len(f.Fix.Commands) > 0 {
			if err := wf("```sh\n"); err != nil {
				return err
			}
			for _, cmd := range f.Fix.Commands {
				if err := wf("%s\n", cmd); err != nil {
					return err
				}
			}
			if err := wf("```\n\n"); err != nil {
				return err
			}
		}
		if len(f.Controls) > 0 {
			refs := make([]string, len(f.Controls))
			for i, c := range f.Controls {
				refs[i] = fmt.Sprintf("%s %s", c.Framework, c.ID)
			}
			if err := wf("**Controls:** %s\n\n", strings.Join(refs, ", ")); err != nil {
				return err
			}
		}
	}

	// 4. Control-coverage matrix
	if err := wf("## Control-Coverage Matrix\n\n"); err != nil {
		return err
	}
	if err := wf("| Framework | Control | Title | Tested | Status |\n"); err != nil {
		return err
	}
	if err := wf("|---|---|---|---|---|\n"); err != nil {
		return err
	}
	for _, row := range CoverageMatrix(r) {
		tested := "Yes"
		if !row.Tested {
			tested = "No"
		}
		if err := wf("| %s | %s | %s | %s | %s |\n",
			row.Framework, row.Control, row.Title, tested, row.Status); err != nil {
			return err
		}
	}
	if err := wf("\n"); err != nil {
		return err
	}

	// 5. Remediation appendix
	if err := wf("## Remediation Appendix\n\n"); err != nil {
		return err
	}
	n := 0
	for _, f := range sorted {
		if !f.IsFail() || f.Status == model.StatusNotAssessed {
			continue
		}
		n++
		if err := wf("%d. **%s** (`%s`)\n\n", n, f.Title, f.CheckID); err != nil {
			return err
		}
		if f.Fix.Summary != "" {
			if err := wf("   %s\n\n", f.Fix.Summary); err != nil {
				return err
			}
		}
		if f.Fix.Diff != "" {
			if err := wf("   ```diff\n   %s\n   ```\n\n", strings.ReplaceAll(f.Fix.Diff, "\n", "\n   ")); err != nil {
				return err
			}
		}
		for _, cmd := range f.Fix.Commands {
			if err := wf("   ```sh\n   %s\n   ```\n\n", cmd); err != nil {
				return err
			}
		}
	}
	if n == 0 {
		if err := wf("No failing findings to remediate.\n\n"); err != nil {
			return err
		}
	}

	// 5b. Scoring breakdown (v2)
	if err := markdownScoringRollup(wf, r); err != nil {
		return err
	}

	// 6. Methodology & scope
	if err := wf("## Methodology & Scope\n\n"); err != nil {
		return err
	}
	methodology := r.Methodology
	if methodology == "" {
		methodology = brandName(r) + " performs a five-phase deterministic audit: " +
			"(1) **Parse** — read and normalise Docker Compose files, environment files, and proxy configuration; " +
			"(2) **Probe** — connect from an external vantage point to observe actual port reachability and TLS state; " +
			"(3) **Correlate** — reconcile declared intent (Compose publish rules) against observed reality; " +
			"(4) **Check** — run the deterministic check library against the correlated context (pure functions, no I/O); " +
			"(5) **Score** — compute the 0–100 posture score from per-severity penalties. " +
			"All deterministic checks are independent of any AI layer; AI explanations are additive and clearly labelled."
	}
	if err := wf("%s\n", methodology); err != nil {
		return err
	}
	if _, tnote := threatDataNote(r.ScannedAt); tnote != "" {
		if err := wf("\n\n%s\n", tnote); err != nil {
			return err
		}
	}

	return nil
}

// markdownScoringRollup writes the v2 scoring breakdown: a per-group sub-scores
// table, a cap-driver callout when a cap lowered the grade, and a not-assessed
// list. It is a no-op for v1 results (empty ScoringModel).
func markdownScoringRollup(wf func(string, ...any) error, r *model.Result) error {
	if r.ScoringModel == "" {
		return nil
	}
	if err := wf("## Scoring Breakdown (%s)\n\n", r.ScoringModel); err != nil {
		return err
	}
	if len(r.SubScores) > 0 {
		if err := wf("| Group | Sub-Score | Not Assessed |\n|---|---|---|\n"); err != nil {
			return err
		}
		for _, gs := range r.SubScores {
			if err := wf("| %s | %d/100 | %d |\n", string(gs.Group), gs.Score, gs.NotAssessed); err != nil {
				return err
			}
		}
		if err := wf("\n"); err != nil {
			return err
		}
	}
	if r.CapDriver != nil {
		if err := wf("> **Grade cap:** `%s` %s — %s (capped to **%s**)\n\n",
			r.CapDriver.CheckID, r.CapDriver.Title, r.CapDriver.Reason, r.CapDriver.Grade); err != nil {
			return err
		}
	}
	if len(r.NotAssessed) > 0 {
		if err := wf("### Not Assessed\n\n"); err != nil {
			return err
		}
		for _, f := range r.NotAssessed {
			if err := wf("- **%s** (`%s`)\n", f.Title, f.CheckID); err != nil {
				return err
			}
		}
		if err := wf("\n"); err != nil {
			return err
		}
	}
	return nil
}

// ─── HTML ────────────────────────────────────────────────────────────────────

// HTML writes the full Security Posture Report as a standalone HTML document.
func HTML(w io.Writer, r *model.Result) error {
	wf := func(format string, args ...any) error {
		_, err := fmt.Fprintf(w, format, args...)
		return err
	}

	he := html.EscapeString

	ratingColor := map[string]string{
		"RED":    "#c0392b",
		"YELLOW": "#f39c12",
		"GREEN":  "#27ae60",
	}[r.Rating]
	if ratingColor == "" {
		ratingColor = "#27ae60"
	}

	if err := wf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s Security Posture Report — %s</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 2rem; color: #222; }
  h1, h2, h3, h4 { color: #1a1a2e; }
  h1 { border-bottom: 3px solid #1a1a2e; padding-bottom: .5rem; }
  h2 { border-bottom: 1px solid #ddd; padding-bottom: .25rem; margin-top: 2rem; }
  .score-badge { display: inline-block; font-size: 2rem; font-weight: bold; color: %s; }
  table { border-collapse: collapse; width: 100%%; margin: 1rem 0; }
  th { background: #1a1a2e; color: white; padding: .5rem .75rem; text-align: left; }
  td { padding: .5rem .75rem; border: 1px solid #ddd; vertical-align: top; }
  tr:nth-child(even) td { background: #f9f9f9; }
  .finding { border: 1px solid #ddd; border-radius: 6px; margin: 1rem 0; padding: 1rem; }
  .finding.critical { border-left: 4px solid #c0392b; }
  .finding.warning  { border-left: 4px solid #f39c12; }
  .finding.info     { border-left: 4px solid #2980b9; }
  .badge { display: inline-block; padding: .2em .6em; border-radius: 3px; font-size: .8em; font-weight: bold; color: white; }
  .badge.critical { background: #c0392b; }
  .badge.warning  { background: #f39c12; }
  .badge.info     { background: #2980b9; }
  pre { background: #f4f4f4; border: 1px solid #ddd; border-radius: 4px; padding: 1rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  code { font-family: "SFMono-Regular", Consolas, monospace; font-size: .9em; }
  .status-fail { color: #c0392b; font-weight: bold; }
  .status-pass { color: #27ae60; font-weight: bold; }
  .meta-table td:first-child { font-weight: bold; width: 180px; }
  @media print { body { max-width: 100%%; padding: 1rem; } }
</style>
</head>
<body>
`, he(brandName(r)), he(r.Target), ratingColor); err != nil {
		return err
	}

	// Cover
	if err := wf("<h1>%s Security Posture Report</h1>\n", he(brandName(r))); err != nil {
		return err
	}
	if err := wf("<p class=\"score-badge\">%d / 100 &nbsp;<span style=\"font-size:1rem;color:#555\">[%s]</span></p>\n\n", r.Score, he(r.Rating)); err != nil {
		return err
	}
	if err := wf("<table class=\"meta-table\">\n"); err != nil {
		return err
	}
	if err := wf("<tr><td>Target</td><td>%s</td></tr>\n", he(r.Target)); err != nil {
		return err
	}
	if err := wf("<tr><td>Scan Timestamp</td><td>%s</td></tr>\n", he(r.ScannedAt.UTC().Format(time.RFC3339))); err != nil {
		return err
	}
	if err := wf("<tr><td>Scanner Version</td><td>%s</td></tr>\n", he(r.Version)); err != nil {
		return err
	}
	if err := wf("<tr><td>Catalog Version</td><td>%s</td></tr>\n", he(catalog.CatalogVersion)); err != nil {
		return err
	}
	if err := wf("</table>\n\n"); err != nil {
		return err
	}

	// Executive summary
	if err := wf("<h2>Executive Summary</h2>\n"); err != nil {
		return err
	}
	summary := r.AISummary
	if summary == "" {
		summary = fmt.Sprintf(
			"%s assessed %s and assigned a posture score of %d/100 (%s). "+
				"It identified %d critical and %d warning findings, with %d checks passing.",
			brandName(r), r.Target, r.Score, r.Rating, r.Counts.Critical, r.Counts.Warning, r.Counts.Passed,
		)
	}
	if err := wf("<p>%s</p>\n\n", he(summary)); err != nil {
		return err
	}

	// AI / MCP Posture panel — only when collection ran or AI/MCP findings exist.
	if hasAIMCPContent(r) {
		if err := wf("<section>\n<h2>AI / MCP Posture</h2>\n"); err != nil {
			return err
		}
		htmlPanelLines := strings.SplitAfter(aiMcpPanel(r), "\n")
		// htmlPanelLines[0] is "AI / MCP Posture\n" — skip it, emit body lines.
		for _, line := range htmlPanelLines[1:] {
			trimmed := strings.TrimRight(line, "\n")
			if trimmed == "" {
				continue
			}
			if err := wf("<p>%s</p>\n", he(trimmed)); err != nil {
				return err
			}
		}
		if err := wf("</section>\n\n"); err != nil {
			return err
		}
	}

	// Findings
	if err := wf("<h2>Findings</h2>\n"); err != nil {
		return err
	}
	sorted := sortedFindings(r.Findings)
	lastSev := model.Severity(-1)
	for _, f := range sorted {
		if f.Passed || f.Severity == model.SeverityOK || f.Status == model.StatusNotAssessed {
			continue // not-assessed findings appear only in the scoring rollup section
		}
		if f.Severity != lastSev {
			if err := wf("<h3>%s Findings</h3>\n", he(f.Severity.Label())); err != nil {
				return err
			}
			lastSev = f.Severity
		}

		sevClass := strings.ToLower(f.Severity.Label())
		if err := wf("<div class=\"finding %s\">\n", sevClass); err != nil {
			return err
		}
		if err := wf("<h4>%s <span class=\"badge %s\">%s</span> %s <code>[%s]</code></h4>\n",
			f.Severity.Emoji(), sevClass, he(f.Severity.Label()), he(f.Title), he(f.CheckID)); err != nil {
			return err
		}

		service := f.Service
		if service == "" {
			service = f.Resource
		}
		if service != "" {
			if err := wf("<p><strong>Service/Resource:</strong> %s</p>\n", he(service)); err != nil {
				return err
			}
		}

		detail := f.Detail
		if f.AIExplanation != "" {
			detail = f.AIExplanation
		}
		if detail != "" {
			if err := wf("<p>%s</p>\n", he(detail)); err != nil {
				return err
			}
		}
		if f.Evidence != "" {
			if err := wf("<p><strong>Evidence:</strong> %s</p>\n", he(f.Evidence)); err != nil {
				return err
			}
		}
		if f.Fix.Summary != "" {
			if err := wf("<p><strong>Fix:</strong> %s</p>\n", he(f.Fix.Summary)); err != nil {
				return err
			}
		}
		if f.Fix.Diff != "" {
			if err := wf("<pre><code>%s</code></pre>\n", he(f.Fix.Diff)); err != nil {
				return err
			}
		}
		if len(f.Fix.Commands) > 0 {
			if err := wf("<pre><code>"); err != nil {
				return err
			}
			for _, cmd := range f.Fix.Commands {
				if err := wf("$ %s\n", he(cmd)); err != nil {
					return err
				}
			}
			if err := wf("</code></pre>\n"); err != nil {
				return err
			}
		}
		if len(f.Controls) > 0 {
			refs := make([]string, len(f.Controls))
			for i, c := range f.Controls {
				refs[i] = he(c.Framework) + " " + he(c.ID)
			}
			if err := wf("<p><strong>Controls:</strong> %s</p>\n", strings.Join(refs, ", ")); err != nil {
				return err
			}
		}
		if err := wf("</div>\n"); err != nil {
			return err
		}
	}

	// Control-coverage matrix
	if err := wf("<h2>Control-Coverage Matrix</h2>\n"); err != nil {
		return err
	}
	if err := wf("<table>\n<tr><th>Framework</th><th>Control</th><th>Title</th><th>Tested</th><th>Status</th></tr>\n"); err != nil {
		return err
	}
	for _, row := range CoverageMatrix(r) {
		tested := "Yes"
		if !row.Tested {
			tested = "No"
		}
		statusClass := "status-pass"
		if row.Status == "FAIL" {
			statusClass = "status-fail"
		}
		if err := wf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td></tr>\n",
			he(row.Framework), he(row.Control), he(row.Title), he(tested), statusClass, he(row.Status)); err != nil {
			return err
		}
	}
	if err := wf("</table>\n\n"); err != nil {
		return err
	}

	// Remediation appendix
	if err := wf("<h2>Remediation Appendix</h2>\n<ol>\n"); err != nil {
		return err
	}
	anyFail := false
	for _, f := range sorted {
		if !f.IsFail() || f.Status == model.StatusNotAssessed {
			continue
		}
		anyFail = true
		if err := wf("<li><strong>%s</strong> (<code>%s</code>)\n", he(f.Title), he(f.CheckID)); err != nil {
			return err
		}
		if f.Fix.Summary != "" {
			if err := wf("<p>%s</p>\n", he(f.Fix.Summary)); err != nil {
				return err
			}
		}
		if f.Fix.Diff != "" {
			if err := wf("<pre><code>%s</code></pre>\n", he(f.Fix.Diff)); err != nil {
				return err
			}
		}
		for _, cmd := range f.Fix.Commands {
			if err := wf("<pre><code>$ %s</code></pre>\n", he(cmd)); err != nil {
				return err
			}
		}
		if err := wf("</li>\n"); err != nil {
			return err
		}
	}
	if !anyFail {
		if err := wf("<li>No failing findings to remediate.</li>\n"); err != nil {
			return err
		}
	}
	if err := wf("</ol>\n\n"); err != nil {
		return err
	}

	// Scoring breakdown (v2)
	if err := htmlScoringRollup(wf, he, r); err != nil {
		return err
	}

	// Methodology
	if err := wf("<h2>Methodology &amp; Scope</h2>\n"); err != nil {
		return err
	}
	methodology := r.Methodology
	if methodology == "" {
		methodology = brandName(r) + " performs a five-phase deterministic audit: " +
			"(1) Parse — read and normalise Docker Compose files, environment files, and proxy configuration; " +
			"(2) Probe — connect from an external vantage point to observe actual port reachability and TLS state; " +
			"(3) Correlate — reconcile declared intent (Compose publish rules) against observed reality; " +
			"(4) Check — run the deterministic check library against the correlated context (pure functions, no I/O); " +
			"(5) Score — compute the 0–100 posture score from per-severity penalties. " +
			"All deterministic checks are independent of any AI layer; AI explanations are additive and clearly labelled."
	}
	if err := wf("<p>%s</p>\n", he(methodology)); err != nil {
		return err
	}
	if _, tnote := threatDataNote(r.ScannedAt); tnote != "" {
		if err := wf("<p>%s</p>\n", he(tnote)); err != nil {
			return err
		}
	}

	if err := wf("</body>\n</html>\n"); err != nil {
		return err
	}

	return nil
}

// htmlScoringRollup writes the v2 scoring breakdown as HTML: a per-group
// sub-scores table, a cap-driver callout, and a not-assessed list. It mirrors
// markdownScoringRollup and is a no-op for v1 results (empty ScoringModel).
func htmlScoringRollup(wf func(string, ...any) error, he func(string) string, r *model.Result) error {
	if r.ScoringModel == "" {
		return nil
	}
	if err := wf("<h2>Scoring Breakdown (%s)</h2>\n", he(r.ScoringModel)); err != nil {
		return err
	}
	if len(r.SubScores) > 0 {
		if err := wf("<table>\n<tr><th>Group</th><th>Sub-Score</th><th>Not Assessed</th></tr>\n"); err != nil {
			return err
		}
		for _, gs := range r.SubScores {
			if err := wf("<tr><td>%s</td><td>%d/100</td><td>%d</td></tr>\n",
				he(string(gs.Group)), gs.Score, gs.NotAssessed); err != nil {
				return err
			}
		}
		if err := wf("</table>\n\n"); err != nil {
			return err
		}
	}
	if r.CapDriver != nil {
		if err := wf("<blockquote><strong>Grade cap:</strong> <code>%s</code> %s &mdash; %s (capped to <strong>%s</strong>)</blockquote>\n\n",
			he(r.CapDriver.CheckID), he(r.CapDriver.Title), he(r.CapDriver.Reason), he(r.CapDriver.Grade)); err != nil {
			return err
		}
	}
	if len(r.NotAssessed) > 0 {
		if err := wf("<h3>Not Assessed</h3>\n<ul>\n"); err != nil {
			return err
		}
		for _, f := range r.NotAssessed {
			if err := wf("<li><strong>%s</strong> (<code>%s</code>)</li>\n", he(f.Title), he(f.CheckID)); err != nil {
				return err
			}
		}
		if err := wf("</ul>\n\n"); err != nil {
			return err
		}
	}
	return nil
}

// ─── PDF ─────────────────────────────────────────────────────────────────────

// PDF writes a multi-section PDF report to w using go-pdf/fpdf.
func PDF(w io.Writer, r *model.Result) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.SetAutoPageBreak(true, 20)
	pageW, _ := pdf.GetPageSize()
	leftM, _, rightM, _ := pdf.GetMargins()
	usableW := pageW - leftM - rightM

	// Helper: safe MultiCell that wraps long text
	cell := func(h float64, txt, align string) {
		pdf.MultiCell(usableW, h, txt, "", align, false)
	}
	ln := func(h float64) { pdf.Ln(h) }

	setFont := func(style string, size float64) {
		pdf.SetFont("Helvetica", style, size)
	}

	// ── Cover page ──────────────────────────────────────────────────────────
	pdf.AddPage()
	setFont("B", 22)
	cell(12, brandName(r), "C")
	setFont("", 14)
	cell(8, "Security Posture Report", "C")
	ln(8)

	setFont("B", 36)
	ratingColor := map[string][3]int{
		"RED":    {192, 57, 43},
		"YELLOW": {243, 156, 18},
		"GREEN":  {39, 174, 96},
	}[r.Rating]
	pdf.SetTextColor(ratingColor[0], ratingColor[1], ratingColor[2])
	cell(18, fmt.Sprintf("%d / 100", r.Score), "C")
	pdf.SetTextColor(0, 0, 0)

	setFont("B", 14)
	cell(10, fmt.Sprintf("[%s]", r.Rating), "C")
	ln(8)

	setFont("", 11)
	cell(7, fmt.Sprintf("Target:         %s", r.Target), "L")
	cell(7, fmt.Sprintf("Scanned At:     %s", r.ScannedAt.UTC().Format(time.RFC3339)), "L")
	cell(7, fmt.Sprintf("Scanner:        %s", r.Version), "L")
	cell(7, fmt.Sprintf("Catalog:        %s", catalog.CatalogVersion), "L")
	ln(4)

	setFont("", 11)
	cell(7, fmt.Sprintf("Critical: %d    Warning: %d    Passed: %d",
		r.Counts.Critical, r.Counts.Warning, r.Counts.Passed), "L")

	// ── Findings ────────────────────────────────────────────────────────────
	pdf.AddPage()
	setFont("B", 16)
	cell(10, "Findings", "L")
	ln(4)

	sorted := sortedFindings(r.Findings)
	lastSev := model.Severity(-1)
	for _, f := range sorted {
		if f.Passed || f.Severity == model.SeverityOK || f.Status == model.StatusNotAssessed {
			continue // not-assessed findings appear only in the scoring rollup section
		}
		if f.Severity != lastSev {
			setFont("B", 13)
			ln(2)
			cell(8, f.Severity.Label()+" Findings", "L")
			lastSev = f.Severity
		}

		setFont("B", 11)
		cell(7, fmt.Sprintf("[%s] %s", f.CheckID, f.Title), "L")

		service := f.Service
		if service == "" {
			service = f.Resource
		}
		if service != "" {
			setFont("I", 10)
			cell(6, "Service/Resource: "+service, "L")
		}

		detail := f.Detail
		if f.AIExplanation != "" {
			detail = f.AIExplanation
		}
		if detail != "" {
			setFont("", 10)
			cell(6, detail, "L")
		}
		if f.Evidence != "" {
			setFont("I", 10)
			cell(6, "Evidence: "+f.Evidence, "L")
		}
		if f.Fix.Summary != "" {
			setFont("B", 10)
			cell(6, "Fix: "+f.Fix.Summary, "L")
		}
		if f.Fix.Diff != "" {
			setFont("", 9)
			cell(5, f.Fix.Diff, "L")
		}
		for _, cmd := range f.Fix.Commands {
			setFont("", 9)
			cell(5, "$ "+cmd, "L")
		}
		if len(f.Controls) > 0 {
			refs := make([]string, len(f.Controls))
			for i, c := range f.Controls {
				refs[i] = c.Framework + " " + c.ID
			}
			setFont("I", 9)
			cell(5, "Controls: "+strings.Join(refs, ", "), "L")
		}
		ln(2)
	}

	// ── Control-Coverage Matrix ──────────────────────────────────────────────
	pdf.AddPage()
	setFont("B", 16)
	cell(10, "Control-Coverage Matrix", "L")
	ln(4)

	colWidths := []float64{30, 25, 75, 20, 20}
	headers := []string{"Framework", "Control", "Title", "Tested", "Status"}
	setFont("B", 10)
	pdf.SetFillColor(26, 26, 46)
	pdf.SetTextColor(255, 255, 255)
	for i, h := range headers {
		pdf.CellFormat(colWidths[i], 8, h, "1", 0, "L", true, 0, "")
	}
	pdf.Ln(-1)
	pdf.SetTextColor(0, 0, 0)

	setFont("", 9)
	fill := false
	for _, row := range CoverageMatrix(r) {
		tested := "Yes"
		if !row.Tested {
			tested = "No"
		}
		if fill {
			pdf.SetFillColor(245, 245, 245)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		fill = !fill

		// Calculate row height for title wrapping
		rowH := 6.0
		pdf.CellFormat(colWidths[0], rowH, row.Framework, "1", 0, "L", true, 0, "")
		pdf.CellFormat(colWidths[1], rowH, row.Control, "1", 0, "L", true, 0, "")
		// Truncate title if too long
		title := row.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		pdf.CellFormat(colWidths[2], rowH, title, "1", 0, "L", true, 0, "")
		pdf.CellFormat(colWidths[3], rowH, tested, "1", 0, "C", true, 0, "")
		if row.Status == "FAIL" {
			pdf.SetTextColor(192, 57, 43)
		} else {
			pdf.SetTextColor(39, 174, 96)
		}
		pdf.CellFormat(colWidths[4], rowH, row.Status, "1", 0, "C", true, 0, "")
		pdf.SetTextColor(0, 0, 0)
		pdf.Ln(-1)
	}

	// ── Remediation Appendix ─────────────────────────────────────────────────
	pdf.AddPage()
	setFont("B", 16)
	cell(10, "Remediation Appendix", "L")
	ln(4)

	n := 0
	for _, f := range sorted {
		if !f.IsFail() || f.Status == model.StatusNotAssessed {
			continue
		}
		n++
		setFont("B", 11)
		cell(7, fmt.Sprintf("%d. [%s] %s", n, f.CheckID, f.Title), "L")
		if f.Fix.Summary != "" {
			setFont("", 10)
			cell(6, f.Fix.Summary, "L")
		}
		if f.Fix.Diff != "" {
			setFont("", 9)
			cell(5, f.Fix.Diff, "L")
		}
		for _, cmd := range f.Fix.Commands {
			setFont("", 9)
			cell(5, "$ "+cmd, "L")
		}
		ln(2)
	}
	if n == 0 {
		setFont("", 11)
		cell(7, "No failing findings to remediate.", "L")
	}

	// ── Scoring Breakdown (v2) ────────────────────────────────────────────────
	if r.ScoringModel != "" {
		pdf.AddPage()
		setFont("B", 16)
		cell(10, fmt.Sprintf("Scoring Breakdown (%s)", r.ScoringModel), "L")
		ln(4)

		if len(r.SubScores) > 0 {
			setFont("B", 11)
			cell(7, "Sub-Scores by Group", "L")
			setFont("", 10)
			for _, gs := range r.SubScores {
				line := fmt.Sprintf("  %-30s %d/100", string(gs.Group), gs.Score)
				if gs.NotAssessed > 0 {
					line += fmt.Sprintf("  (%d not assessed)", gs.NotAssessed)
				}
				cell(6, line, "L")
			}
			ln(3)
		}

		if r.CapDriver != nil {
			setFont("B", 11)
			cap := fmt.Sprintf("Grade cap: [%s] %s — %s (capped to %s)",
				r.CapDriver.CheckID, r.CapDriver.Title, r.CapDriver.Reason, r.CapDriver.Grade)
			pdf.SetTextColor(192, 57, 43)
			cell(7, cap, "L")
			pdf.SetTextColor(0, 0, 0)
			ln(3)
		}

		if len(r.NotAssessed) > 0 {
			setFont("B", 11)
			cell(7, fmt.Sprintf("Not Assessed (%d)", len(r.NotAssessed)), "L")
			setFont("", 10)
			for _, f := range r.NotAssessed {
				cell(6, fmt.Sprintf("  - %s [%s]", f.Title, f.CheckID), "L")
			}
		}
	}

	return pdf.Output(w)
}
