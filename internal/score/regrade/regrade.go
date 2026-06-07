// Package regrade replays stored scan Results through both the v1 and v2
// scoring engines and tallies the grade transitions. It is the offline
// safety net we run before flipping v2 to the default scoring model: it
// answers "how many boxes will re-grade, and in which direction." Pure: it
// performs no I/O and is deterministic for a given input.
package regrade

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/score"
)

// RegradeReport summarizes a v1->v2 regrade over a batch of stored Results.
type RegradeReport struct {
	// Total is the number of Results examined.
	Total int `json:"total"`
	// Transitions counts each "V1->V2" grade pair, e.g. "GREEN->RED".
	Transitions map[string]int `json:"transitions"`
	// Worsened is the count of Results whose grade got stricter under v2.
	Worsened int `json:"worsened"`
	// Improved is the count of Results whose grade got more lenient under v2.
	Improved int `json:"improved"`
}

// gradeRank delegates to score.GradeRank so there is a single source of truth.
func gradeRank(grade string) int { return score.GradeRank(grade) }

// Regrade computes the v1 and v2 grade for each Result and tallies the
// transitions. v1 grade is score.Rating(score.Compute(...)); v2 grade is the
// post-cap rating returned by score.ComputeV2. The returned report always has
// a non-nil Transitions map (empty for empty input).
func Regrade(results []model.Result) RegradeReport {
	rep := RegradeReport{
		Total:       len(results),
		Transitions: map[string]int{},
	}
	for i := range results {
		findings := results[i].Findings
		v1n, _ := score.Compute(findings)
		v1 := score.Rating(v1n)
		_, v2, _, _ := score.ComputeV2(findings)
		rep.Transitions[v1+"->"+v2]++
		switch {
		case gradeRank(v2) < gradeRank(v1):
			rep.Worsened++
		case gradeRank(v2) > gradeRank(v1):
			rep.Improved++
		}
	}
	return rep
}

// Summary renders a deterministic, human-readable regrade report: a sorted
// transition table, the Worsened/Improved tallies, and the headline count of
// boxes that re-grade GREEN->RED — the number we gate the v2 cutover on.
func (r RegradeReport) Summary() string {
	keys := make([]string, 0, len(r.Transitions))
	for k := range r.Transitions {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	fmt.Fprintf(&b, "regrade: %d scans (v1 -> v2)\n", r.Total)
	fmt.Fprintln(&b, "transition        count")
	fmt.Fprintln(&b, "----------------- -----")
	for _, k := range keys {
		fmt.Fprintf(&b, "%-17s %5d\n", k, r.Transitions[k])
	}
	fmt.Fprintf(&b, "worsened: %d  improved: %d\n", r.Worsened, r.Improved)
	n := r.Transitions["GREEN->RED"]
	noun := "boxes"
	if n == 1 {
		noun = "box"
	}
	fmt.Fprintf(&b, "%d %s will re-grade GREEN->RED\n", n, noun)
	return b.String()
}
