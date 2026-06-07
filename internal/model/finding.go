// Package model defines the stable, shared data contract used by every part of
// Keelix: parsers, the prober, the check library, scoring, compliance
// mapping, reporters, and the AI layer. Nothing in this package performs I/O.
package model

// Severity is the RED / YELLOW / GREEN rating of a finding.
type Severity int

const (
	// SeverityOK is a passed check (GREEN).
	SeverityOK Severity = iota
	// SeverityInfo is informational, non-failing context (GREEN).
	SeverityInfo
	// SeverityWarning is a non-critical issue that should be fixed (YELLOW).
	SeverityWarning
	// SeverityCritical is an exploitable exposure that must be fixed (RED).
	SeverityCritical
)

// String returns the lowercase machine name of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "ok"
	}
}

// Rating returns the RED/YELLOW/GREEN traffic-light rating.
func (s Severity) Rating() string {
	switch s {
	case SeverityCritical:
		return "RED"
	case SeverityWarning:
		return "YELLOW"
	default:
		return "GREEN"
	}
}

// Emoji returns the traffic-light emoji used in the terminal report.
func (s Severity) Emoji() string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityWarning:
		return "🟡"
	default:
		return "🟢"
	}
}

// Label returns the human label used in reports (CRITICAL/WARNING/OK).
func (s Severity) Label() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityWarning:
		return "WARNING"
	case SeverityInfo:
		return "INFO"
	default:
		return "OK"
	}
}

// Fix is the concrete remediation for a finding.
type Fix struct {
	// Summary is a one-line plain-English instruction.
	Summary string `json:"summary"`
	// Diff is a unified-diff-ish or before/after config change the user applies.
	Diff string `json:"diff,omitempty"`
	// Commands are shell commands to run (e.g. firewall rules).
	Commands []string `json:"commands,omitempty"`
	// DocURL is an optional reference link.
	DocURL string `json:"doc_url,omitempty"`
}

// ControlRef maps a finding to a specific compliance control an auditor checks.
type ControlRef struct {
	// Framework is "SOC2", "ISO27001", or "CIS-Docker".
	Framework string `json:"framework"`
	// ID is the control identifier, e.g. "CC6.6", "A.8.20", "5.7".
	ID string `json:"id"`
	// Title is the human name of the control.
	Title string `json:"title"`
}

// Finding is a single result produced by a check. A passed check is also a
// Finding (Severity == SeverityOK, Passed == true) so reports can show what was
// tested and passed — this is what makes the output audit-grade evidence.
type Finding struct {
	// CheckID is the stable identifier of the check, e.g. "EXP001".
	CheckID string `json:"check_id"`
	// Group is the check library group this finding belongs to.
	Group CheckGroup `json:"group"`
	// Title is a short headline, e.g. "PostgreSQL reachable from the internet (port 5432)".
	Title string `json:"title"`
	// Severity is the RED/YELLOW/GREEN rating.
	Severity Severity `json:"severity"`
	// Passed indicates this finding represents a check that passed.
	Passed bool `json:"passed"`
	// Service is the affected compose service, if applicable.
	Service string `json:"service,omitempty"`
	// Resource is the affected resource, e.g. "port 5432" or "container app".
	Resource string `json:"resource,omitempty"`
	// Detail is the deterministic plain-English reason this matters.
	Detail string `json:"detail"`
	// Evidence is the ground-truth observation that triggered the finding.
	Evidence string `json:"evidence,omitempty"`
	// Fix is the concrete remediation.
	Fix Fix `json:"fix"`
	// Controls are the compliance control mappings (filled by the compliance layer).
	Controls []ControlRef `json:"controls,omitempty"`
	// AIExplanation is an optional richer explanation from the AI layer.
	AIExplanation string `json:"ai_explanation,omitempty"`
	// AIDiff is an optional generated remediation diff from the AI layer.
	AIDiff string `json:"ai_diff,omitempty"`
	// Metadata carries structured details for downstream consumers.
	Metadata map[string]string `json:"metadata,omitempty"`
	// BaseImpact is the 0-10 intrinsic impact, sourced from catalog.Entry.BaseImpact.
	BaseImpact float64 `json:"base_impact,omitempty"`
	// Confidence is how sure the check is; zero value = ConfidenceHigh.
	Confidence Confidence `json:"confidence,omitempty"`
	// ExposureClass is where the resource is actually reachable from; set by
	// correlate.Classify, NOT by checks.
	ExposureClass ExposureClass `json:"exposure_class,omitempty"`
	// Mitigations are observed compensating controls; set by correlate.Classify.
	Mitigations []string `json:"mitigations,omitempty"`
	// Fatal marks a check whose failure can drive an overall RED cap; sourced
	// from catalog.Entry.Fatal.
	Fatal bool `json:"fatal,omitempty"`
	// Status records whether the check ran; zero value = StatusAssessed.
	Status FindingStatus `json:"status,omitempty"`
}

// IsFail reports whether the finding represents a problem (warning or critical).
func (f Finding) IsFail() bool {
	return f.Severity == SeverityWarning || f.Severity == SeverityCritical
}

// Confidence is how sure a check is that the finding is real and exploitable.
// It scales a finding's risk contribution in the v2 score. Zero value is High.
type Confidence int

const (
	// ConfidenceHigh is a directly observed, unambiguous finding (full weight).
	ConfidenceHigh Confidence = iota
	// ConfidenceMedium is a likely-but-inferred finding.
	ConfidenceMedium
	// ConfidenceLow is a heuristic or weakly-supported finding.
	ConfidenceLow
)

// Multiplier is the risk weight applied to a finding at this confidence:
// High 1.0, Medium 0.6, Low 0.3.
func (c Confidence) Multiplier() float64 {
	switch c {
	case ConfidenceMedium:
		return 0.6
	case ConfidenceLow:
		return 0.3
	default:
		return 1.0
	}
}

// FindingStatus records whether a check actually ran for this finding. Findings
// that could not be assessed are excluded from the score numerator and
// denominator. Zero value is Assessed.
type FindingStatus int

const (
	// StatusAssessed means the check ran and this result is scored.
	StatusAssessed FindingStatus = iota
	// StatusNotAssessed means the check could not run (e.g. inside-out data
	// unavailable); it is reported but excluded from scoring.
	StatusNotAssessed
)

// ExposureClass is where a finding's resource is actually reachable from. It is
// set by correlate.Classify (never by checks) and scales risk in the v2 score.
type ExposureClass int

const (
	// ExposureUnknown means reachability could not be determined.
	ExposureUnknown ExposureClass = iota
	// ExposureLocalhost is reachable only on 127.0.0.1/::1.
	ExposureLocalhost
	// ExposureOverlay is reachable only on an overlay/mesh (e.g. Tailscale, WireGuard).
	ExposureOverlay
	// ExposureLAN is reachable on a private RFC1918 network.
	ExposureLAN
	// ExposureFiltered is published to all interfaces but firewall-blocked from outside.
	ExposureFiltered
	// ExposureInternet is confirmed reachable from the public internet.
	ExposureInternet
)

// Multiplier is the risk weight for this exposure: Unknown 0.5, Localhost 0.10,
// Overlay 0.15, LAN 0.35, Filtered 0.50, Internet 1.00.
func (e ExposureClass) Multiplier() float64 {
	switch e {
	case ExposureLocalhost:
		return 0.10
	case ExposureOverlay:
		return 0.15
	case ExposureLAN:
		return 0.35
	case ExposureFiltered:
		return 0.50
	case ExposureInternet:
		return 1.00
	default: // ExposureUnknown
		return 0.5
	}
}

// CanCapRed reports whether a finding at this exposure may drive an overall RED
// cap. Only LAN, Filtered, and Internet exposures qualify.
func (e ExposureClass) CanCapRed() bool {
	switch e {
	case ExposureLAN, ExposureFiltered, ExposureInternet:
		return true
	default:
		return false
	}
}
