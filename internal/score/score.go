// Package score computes the 0-100 posture score and the overall RED/YELLOW/
// GREEN rating from a set of findings. The formula is deterministic and
// documented so the number is defensible in an audit context.
package score

import "github.com/jwlamon/keelix/internal/model"

// Per-finding penalties subtracted from a perfect score of 100.
const (
	penaltyCritical = 10.0
	penaltyWarning  = 3.0
	penaltyInfo     = 0.5
)

// Rating thresholds (inclusive lower bounds).
const (
	greenMin  = 85
	yellowMin = 50
)

// Compute returns the posture score (0-100) and per-severity counts for the
// given findings. Passing findings raise the visible coverage but do not add
// points beyond the starting 100; failures subtract by severity.
func Compute(findings []model.Finding) (int, model.Counts) {
	counts := Count(findings)
	penalty := float64(counts.Critical)*penaltyCritical +
		float64(counts.Warning)*penaltyWarning +
		float64(counts.Info)*penaltyInfo
	s := 100.0 - penalty
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return int(s + 0.5), counts
}

// Count tallies findings by severity. Findings with StatusNotAssessed are
// excluded because they are tracked separately in Result.NotAssessed and must
// not inflate the scored counts.
func Count(findings []model.Finding) model.Counts {
	var c model.Counts
	for _, f := range findings {
		if f.Status == model.StatusNotAssessed {
			continue
		}
		switch f.Severity {
		case model.SeverityCritical:
			c.Critical++
		case model.SeverityWarning:
			c.Warning++
		case model.SeverityInfo:
			c.Info++
		default:
			if f.Passed {
				c.Passed++
			}
		}
	}
	return c
}

// Rating maps a numeric score to the overall RED/YELLOW/GREEN rating.
func Rating(s int) string {
	switch {
	case s >= greenMin:
		return "GREEN"
	case s >= yellowMin:
		return "YELLOW"
	default:
		return "RED"
	}
}
