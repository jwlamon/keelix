package report

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/model"
)

// aiMcpPanel renders the leading AI/MCP posture summary from an already-computed
// Result. Pure: no I/O, no scoring. Returns "" only if the caller should skip it
// (it never does today — it always renders at least the none/not-assessed line).
func aiMcpPanel(r *model.Result) string {
	agt := subScore(r, model.GroupAIAgent)
	mcp := subScore(r, model.GroupMCP)

	// Partition AGT/MCP findings.
	var agtFail, mcpFail, agtNA, mcpNA int
	var trifecta, autonomy bool
	for i := range r.Findings {
		f := &r.Findings[i]
		switch f.Group {
		case model.GroupAIAgent:
			if f.Status == model.StatusNotAssessed {
				agtNA++
			} else if !f.Passed {
				agtFail++
				if f.CheckID == "AGT002" {
					trifecta = true
				}
				if f.CheckID == "AGT001" || f.CheckID == "AGT006" {
					autonomy = true
				}
			}
		case model.GroupMCP:
			if f.Status == model.StatusNotAssessed {
				mcpNA++
			} else if !f.Passed {
				mcpFail++
			}
		}
	}

	var b strings.Builder
	b.WriteString("AI / MCP Posture\n")

	// None detected at all (no findings in either group).
	if agt == nil && mcp == nil {
		b.WriteString("  No AI agents or MCP servers detected on this box — nothing to assess here.\n")
		return b.String()
	}

	// Cap headline.
	if r.CapDriver != nil {
		if strings.HasPrefix(r.CapDriver.CheckID, "AGT") || strings.HasPrefix(r.CapDriver.CheckID, "MCP") {
			b.WriteString(fmt.Sprintf("  ⚠ AI/MCP posture capped this box %s — %s\n", r.CapDriver.Grade, r.CapDriver.Reason))
		} else {
			b.WriteString(fmt.Sprintf("  (overall grade capped by %s to %s — see Scoring Breakdown for details)\n", r.CapDriver.CheckID, r.CapDriver.Grade))
		}
	}

	b.WriteString(groupLine("AI agents", agt, agtFail, agtNA, map[string]bool{"trifecta": trifecta, "autonomy": autonomy}))
	b.WriteString(groupLine("MCP servers", mcp, mcpFail, mcpNA, nil))
	return b.String()
}

func subScore(r *model.Result, g model.CheckGroup) *model.GroupScore {
	for i := range r.SubScores {
		if r.SubScores[i].Group == g {
			return &r.SubScores[i]
		}
	}
	return nil
}

func groupLine(label string, gs *model.GroupScore, fail, na int, flags map[string]bool) string {
	if gs == nil {
		return fmt.Sprintf("  %s: none detected\n", label)
	}
	parts := []string{fmt.Sprintf("sub-score %d/100", gs.Score)}
	if fail > 0 {
		parts = append(parts, fmt.Sprintf("%d issue(s)", fail))
	}
	if na > 0 {
		parts = append(parts, fmt.Sprintf("%d not assessed", na))
	}
	if fail == 0 && na == 0 {
		parts = append(parts, "no issues")
	}
	if flags["trifecta"] {
		parts = append(parts, "LETHAL TRIFECTA present")
	}
	if flags["autonomy"] {
		parts = append(parts, "unattended autonomy")
	}
	return fmt.Sprintf("  %s: %s\n", label, strings.Join(parts, " · "))
}
