package model

// GroupScore is the v2 sub-score for a single check group: a 0-100 number over
// that group's assessed (failing + passing) checks, plus how many checks in the
// group could not be assessed.
type GroupScore struct {
	Group       CheckGroup `json:"group"`
	Score       int        `json:"score"`
	NotAssessed int        `json:"not_assessed,omitempty"`
}

// CapDriver names the single finding that imposed an overall grade cap below the
// numeric band (e.g. a fatal internet-exposed datastore forcing RED). It is set
// only when a cap actually lowered the grade.
type CapDriver struct {
	CheckID string `json:"check_id"`
	Title   string `json:"title"`
	Reason  string `json:"reason"`
	// Grade is the cap this finding imposed: "RED" or "YELLOW".
	Grade string `json:"grade"`
}
