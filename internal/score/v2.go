package score

import (
	"math"

	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/threatfeed"
)

// infoCapPoints is the aggregate ceiling on the risk contribution of all
// SeverityInfo findings combined. Info-tier noise can never dominate the score.
const infoCapPoints = 5.0

// threat returns the exploitability weight of a finding from the embedded
// EPSS/KEV snapshot. Findings carry their CVE in Metadata["cve"]; non-CVE
// findings (the vast majority) return 1.0, byte-identical to the SP0–SP3 stub.
//
//   - no CVE                 → 1.0
//   - KEV-listed CVE         → 1.0 (strongest "patch now" signal)
//   - EPSS percentile p      → 0.3 + 0.7*p  (range [0.3,1.0])
//   - EPSS-absent CVE        → 1.0 (fail safe to full weight)
//
// This is the ONLY change to the scoring math; risk() and ComputeV2
// normalization are untouched.
func threat(f model.Finding) float64 {
	cve := f.Metadata["cve"]
	if cve == "" {
		return 1.0
	}
	if threatfeed.KEVListed(cve) {
		return 1.0
	}
	if p, ok := threatfeed.EPSSPercentile(cve); ok {
		return 0.3 + 0.7*p
	}
	return 1.0
}

// risk is the exposure-, confidence-, and threat-weighted impact of a single
// FAILING finding. It is the numerator term in the v2 ratio.
//
//	risk = BaseImpact × ExposureClass.Multiplier × threat × Confidence.Multiplier
func risk(f model.Finding) float64 {
	expMult := f.ExposureClass.Multiplier()
	// AI/MCP risk does not depend on network reachability: a misconfigured local
	// agent (auto-approval, plaintext MCP secret, lethal-trifecta capability) is
	// dangerous regardless of whether anything listens on a routable port. Score
	// the AI/MCP domain at full weight — no localhost/exposure discount — so its
	// criticals actually move the blended grade.
	if model.DomainOf(f.Group) == model.DomainAIMCP {
		expMult = 1.0
	}
	return f.BaseImpact *
		expMult *
		threat(f) *
		f.Confidence.Multiplier()
}

// maxrisk is the denominator term for a finding whose check ran (Status ==
// StatusAssessed), whether it passed or failed. It is the intrinsic ceiling of
// the check: its BaseImpact, with no exposure/confidence discounting.
func maxrisk(f model.Finding) float64 { return f.BaseImpact }

// applyKEVFatal escalates findings that carry a KEV-listed CVE at a routable
// exposure to Fatal, so the existing network RED cap fires for them. It runs
// at the top of ComputeV2, AFTER correlate.Classify has set ExposureClass.
//
// Preconditions for escalation (all must hold):
//   - finding carries a CVE in Metadata["cve"]
//   - that CVE is on the CISA KEV catalog (threatfeed.KEVListed)
//   - ExposureClass.CanCapRed() — i.e. LAN, Filtered, or Internet
//   - Severity == SeverityCritical — a future Warning/Info CVE finding must
//     not be silently promoted to a RED-cap driver
//
// Localhost/Overlay/Unknown KEV findings are NOT escalated: they still weigh
// threat()=1.0 but never drive the RED cap. The returned slice is a copy with
// the escalation applied; the caller's slice is not mutated, so the engine's
// Result.Findings keep their original Fatal flags for rendering.
func applyKEVFatal(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		cve := out[i].Metadata["cve"]
		if cve == "" {
			continue
		}
		if threatfeed.KEVListed(cve) &&
			out[i].ExposureClass.CanCapRed() &&
			out[i].Severity == model.SeverityCritical {
			out[i].Fatal = true
		}
	}
	return out
}

// ComputeV2 is the v2 posture engine. It returns the numeric 0-100 posture
// score, the overall RED/YELLOW/GREEN rating AFTER caps, the per-CheckGroup
// sub-scores, and the cap-driver (non-nil only when a cap lowered the grade
// below the numeric band).
//
// Numerator/denominator are restricted to checks that RAN (Status ==
// StatusAssessed). Passing assessed checks contribute to the denominator only;
// not-assessed findings are excluded from both sums.
func ComputeV2(findings []model.Finding) (numeric int, rating string, subs []model.GroupScore, cap *model.CapDriver) {
	// KEV-listed CVEs at a routable exposure escalate to Fatal so the existing
	// network RED cap fires. Applied to a copy; the input slice is untouched.
	findings = applyKEVFatal(findings)
	numeric = computeNumeric(findings)
	b := band(numeric)
	capGrade, driver := computeCap(findings)
	rating = worst(b, capGrade)
	subs = computeSubScores(findings)
	if gradeRank(rating) < gradeRank(b) {
		cap = driver
	}
	return numeric, rating, subs, cap
}

// computeSubScores returns one GroupScore per CheckGroup that has at least one
// finding, in canonical model.GroupOrder. Each Score is computeNumeric scoped
// to that group; NotAssessed counts the group's not-assessed findings.
func computeSubScores(findings []model.Finding) []model.GroupScore {
	byGroup := make(map[model.CheckGroup][]model.Finding)
	naByGroup := make(map[model.CheckGroup]int)
	for _, f := range findings {
		byGroup[f.Group] = append(byGroup[f.Group], f)
		if f.Status == model.StatusNotAssessed {
			naByGroup[f.Group]++
		}
	}
	var out []model.GroupScore
	for _, g := range model.GroupOrder {
		group, ok := byGroup[g]
		if !ok {
			continue
		}
		out = append(out, model.GroupScore{
			Group:       g,
			Score:       computeNumeric(group),
			NotAssessed: naByGroup[g],
		})
	}
	return out
}

// GradeRank orders grades for comparison. GREEN(2) > YELLOW(1) > RED(0):
// a LOWER rank is a WORSE grade.
func GradeRank(grade string) int {
	switch grade {
	case "GREEN":
		return 2
	case "YELLOW":
		return 1
	default:
		return 0
	}
}

// gradeRank is the unexported alias kept for package-internal callers.
func gradeRank(grade string) int { return GradeRank(grade) }

// worst returns the more severe of two grades (RED worst, GREEN best).
func worst(a, b string) string {
	if gradeRank(b) < gradeRank(a) {
		return b
	}
	return a
}

// computeCap applies the SP0 + SP1a cap rules and returns the imposed cap grade
// plus the single highest-risk finding that justifies it (the cap driver). When
// no cap fires it returns ("GREEN", nil).
//
// Rules (evaluated over the finding set):
//   - Network RED cap  : finding Fatal && IsFail() && Confidence==ConfidenceHigh &&
//     ExposureClass.CanCapRed().
//   - Autonomy RED cap : finding Fatal && IsFail() && Confidence!=ConfidenceLow &&
//     DomainOf(Group)==DomainAIMCP.
//   - YELLOW cap       : finding Confidence==ConfidenceHigh &&
//     Severity==SeverityCritical && ExposureClass==ExposureInternet &&
//     len(Mitigations)==0.
//
// RED (either branch) takes precedence over YELLOW. Between the two RED
// branches the higher-risk finding wins. The resulting CapDriver.Reason
// differentiates network from autonomy.
func computeCap(findings []model.Finding) (string, *model.CapDriver) {
	var networkDriver, autonomyDriver, yellowDriver *model.Finding
	var networkRisk, autonomyRisk, yellowRisk float64

	for i := range findings {
		f := findings[i]
		if f.Status != model.StatusAssessed {
			continue
		}

		// Network RED cap (SP0, unchanged).
		if f.Fatal && f.IsFail() && f.Confidence == model.ConfidenceHigh && f.ExposureClass.CanCapRed() {
			if networkDriver == nil || risk(f) > networkRisk {
				ff := f
				networkDriver = &ff
				networkRisk = risk(f)
			}
		}

		// Autonomy RED cap (SP1a): Fatal AI/MCP capability, not Low confidence.
		if f.Fatal && f.IsFail() &&
			f.Confidence != model.ConfidenceLow &&
			model.DomainOf(f.Group) == model.DomainAIMCP {
			if autonomyDriver == nil || risk(f) > autonomyRisk {
				ff := f
				autonomyDriver = &ff
				autonomyRisk = risk(f)
			}
		}

		// YELLOW cap (SP0, unchanged).
		if f.Confidence == model.ConfidenceHigh &&
			f.Severity == model.SeverityCritical &&
			f.ExposureClass == model.ExposureInternet &&
			len(f.Mitigations) == 0 {
			if yellowDriver == nil || risk(f) > yellowRisk {
				ff := f
				yellowDriver = &ff
				yellowRisk = risk(f)
			}
		}
	}

	// Choose the higher-risk RED driver when both branches fire.
	if networkDriver != nil || autonomyDriver != nil {
		if networkDriver != nil && (autonomyDriver == nil || networkRisk >= autonomyRisk) {
			return "RED", &model.CapDriver{
				CheckID: networkDriver.CheckID,
				Title:   networkDriver.Title,
				Reason:  "fatal exposure reachable from a routable network",
				Grade:   "RED",
			}
		}
		return "RED", &model.CapDriver{
			CheckID: autonomyDriver.CheckID,
			Title:   autonomyDriver.Title,
			Reason:  "dangerous AI agent / MCP capability",
			Grade:   "RED",
		}
	}

	if yellowDriver != nil {
		return "YELLOW", &model.CapDriver{
			CheckID: yellowDriver.CheckID,
			Title:   yellowDriver.Title,
			Reason:  "unmitigated critical service reachable from the internet",
			Grade:   "YELLOW",
		}
	}
	return "GREEN", nil
}

// band maps a numeric 0-100 to its uncapped GREEN/YELLOW/RED grade using the
// same thresholds as v1's Rating. Caps may later worsen this band.
func band(numeric int) string {
	switch {
	case numeric >= greenMin:
		return "GREEN"
	case numeric >= yellowMin:
		return "YELLOW"
	default:
		return "RED"
	}
}

// computeNumeric implements the normalized v2 ratio:
//
//	numeric = round(100 * (1 - sum(risk_i)/sum(maxrisk_i))), floored at 0
//
// over assessed findings only (failing => risk+maxrisk; passing => maxrisk).
// Info-tier risk is accumulated separately and clamped to infoCapPoints before
// entering the numerator, so info noise can never dominate the score.
// denom==0 => 100.
func computeNumeric(findings []model.Finding) int {
	var sumRisk, sumInfoRisk, sumMax float64
	for _, f := range findings {
		if f.Status != model.StatusAssessed {
			continue // not-assessed: excluded from both sums.
		}
		sumMax += maxrisk(f)
		switch {
		case f.Severity == model.SeverityInfo:
			sumInfoRisk += risk(f) // clamped in aggregate below.
		case f.IsFail():
			sumRisk += risk(f)
		default:
			// passing assessed check: denominator only.
		}
	}
	if sumInfoRisk > infoCapPoints {
		sumInfoRisk = infoCapPoints
	}
	sumRisk += sumInfoRisk
	if sumMax == 0 {
		return 100
	}
	n := 100.0 * (1.0 - sumRisk/sumMax)
	if n < 0 {
		n = 0
	}
	return int(math.Round(n))
}
