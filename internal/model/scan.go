package model

import "time"

// ScanOptions controls how a scan runs.
type ScanOptions struct {
	// Host is the target host (FQDN or IP) probed outside-in.
	Host string
	// Domains are additional domains declared for the stack.
	Domains []string
	// NoProbe disables outside-in network probing (offline / static analysis only).
	NoProbe bool
	// ProbeURL, if set, is a remote probe service used as the external vantage point.
	ProbeURL string
	// ProbeTimeout per-port.
	ProbeTimeout time.Duration
	// CI mode: machine-friendly behavior, exit non-zero on critical.
	CI bool
	// AIEnabled requests the AI explain/narrate layer (best-effort).
	AIEnabled bool
	// IntendedPorts are ports the operator explicitly marks as intended-public.
	IntendedPorts []int
	// PolicyPath is the path to an optional JSON policy file for org-defined custom rules.
	// Loaded and evaluated outside the registered-check registry; does not affect
	// catalog or compliance mappings.
	PolicyPath string
	// BrandName is the human-facing product name used in report output (default "Keelix").
	BrandName string
	// Collect enables inside-out fact collection on the local host.
	Collect bool
	// CollectPrivileged requests privileged collectors (e.g. socket→PID owner).
	CollectPrivileged bool
	// SignalsPath, if set, loads a pre-recorded Signals JSON instead of running
	// live collection (produced by `keelix collect`). Takes precedence over Collect.
	SignalsPath string

	// ComposePath is the path to the Docker Compose file being scanned, if any.
	// Empty on a whole-box (no-compose) quickstart.
	ComposePath string

	// MCPProbeEnabled requests the consent-gated, sandboxed ACTIVE MCP probe
	// (SP1b). It is OFF by default because the probe executes untrusted MCP
	// server code in a best-effort sandbox.
	MCPProbeEnabled bool
	// MCPProbeConsent records that the operator explicitly consented to running
	// the active probe. The CLI sets it from --probe-mcp-yes or an interactive
	// y/N prompt on a TTY. The engine NEVER runs the probe unless this is true.
	MCPProbeConsent bool
	// MCPProbeUnsandboxed disables the best-effort sandbox for the probe. Off by
	// default; intended only for diagnosing sandbox-incompatible MCP servers.
	MCPProbeUnsandboxed bool
}

// Logger is a minimal logging sink so packages avoid a logging dependency.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
}

// NopLogger discards all log output.
type NopLogger struct{}

func (NopLogger) Debugf(string, ...any) {}
func (NopLogger) Infof(string, ...any)  {}
func (NopLogger) Warnf(string, ...any)  {}

// ScanContext is the read-only input every Check receives. Checks are pure
// functions of this context: they perform no I/O, which makes them fully
// deterministic and unit-testable. All network observation lives in Probe.
type ScanContext struct {
	// Stack is the parsed compose deployment + surrounding config.
	Stack *Stack
	// Options are the scan options.
	Options ScanOptions
	// Probe holds outside-in observations; nil when probing is disabled.
	Probe *ProbeResult
	// Collector holds inside-out (on-host) facts; nil when collection is
	// disabled or unavailable. Parallel to Probe.
	Collector *Signals
	// Intended maps a port number to whether it is intended to be public.
	// Populated by the correlation/intent layer; checks use it to cut false positives.
	Intended map[int]bool
	// Logger for optional diagnostics.
	Logger Logger
}

// Log returns a non-nil logger.
func (c *ScanContext) Log() Logger {
	if c.Logger == nil {
		return NopLogger{}
	}
	return c.Logger
}

// PortProbe is the observed state of a single port from the external vantage point.
type PortProbe struct {
	Port int `json:"port"`
	// Open is true if a TCP connection succeeded from outside.
	Open bool `json:"open"`
	// Protocol guessed from the port/banner.
	Protocol string `json:"protocol,omitempty"`
	// Service is the guessed service name (e.g. "postgresql").
	Service string `json:"service,omitempty"`
	// Banner is any banner text captured (truncated).
	Banner string `json:"banner,omitempty"`
	// TLS holds certificate info if the port spoke TLS.
	TLS *CertInfo `json:"tls,omitempty"`
}

// DNSRecord is a resolved DNS record relevant to the scan.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // A, AAAA, CNAME, etc.
	Value string `json:"value"`
	// Wildcard is true if the record was matched via a wildcard.
	Wildcard bool `json:"wildcard,omitempty"`
	// Dangling is true if the target does not resolve / is unclaimed (takeover risk).
	Dangling bool `json:"dangling,omitempty"`
}

// CertInfo describes a TLS certificate observed on a public endpoint.
type CertInfo struct {
	Endpoint   string    `json:"endpoint"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Expired    bool      `json:"expired"`
	// DaysUntilExpiry is negative if already expired.
	DaysUntilExpiry int `json:"days_until_expiry"`
	// TLSVersion is the negotiated version, e.g. "TLS 1.3".
	TLSVersion string `json:"tls_version,omitempty"`
	// WeakCipher is true if a weak cipher suite was negotiated.
	WeakCipher bool   `json:"weak_cipher,omitempty"`
	CipherName string `json:"cipher_name,omitempty"`
}

// ProbeResult is the full set of outside-in observations for a target.
type ProbeResult struct {
	Host         string              `json:"host"`
	VantagePoint string              `json:"vantage_point,omitempty"`
	ProbedAt     time.Time           `json:"probed_at"`
	ResolvedIPs  []string            `json:"resolved_ips,omitempty"`
	DomainIPs    map[string][]string `json:"domain_ips,omitempty"`
	// Reachable maps a port to its observed external state.
	Reachable    map[int]PortProbe `json:"reachable,omitempty"`
	DNSRecords   []DNSRecord       `json:"dns_records,omitempty"`
	Certificates []CertInfo        `json:"certificates,omitempty"`
	// Errors records non-fatal probing problems (e.g. host unresolvable).
	Errors []string `json:"errors,omitempty"`
}

// IsReachable reports whether the given port was reachable from outside.
func (p *ProbeResult) IsReachable(port int) bool {
	if p == nil {
		return false
	}
	pp, ok := p.Reachable[port]
	return ok && pp.Open
}

// Counts summarizes finding severities.
type Counts struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Passed   int `json:"passed"`
	Info     int `json:"info"`
}

// Result is the complete output of a scan.
type Result struct {
	Target    string       `json:"target"`
	ScannedAt time.Time    `json:"scanned_at"`
	Version   string       `json:"version"`
	Score     int          `json:"score"`
	Rating    string       `json:"rating"` // RED/YELLOW/GREEN overall
	Counts    Counts       `json:"counts"`
	Findings  []Finding    `json:"findings"`
	Stack     *Stack       `json:"stack,omitempty"`
	Probe     *ProbeResult `json:"probe,omitempty"`
	// Methodology is a short scope/method statement for the evidence report.
	Methodology string `json:"methodology,omitempty"`
	// AISummary is an optional executive summary from the AI layer.
	AISummary string `json:"ai_summary,omitempty"`
	// BrandName is the human-facing product name used in report output.
	// Defaults to "Keelix" when empty.
	BrandName string `json:"brand_name,omitempty"`
	// Collector holds inside-out facts; nil when collection was disabled/unavailable.
	Collector *Signals `json:"collector,omitempty"`
	// ScoringModel identifies the scoring engine that produced Score/Rating, e.g. "v2".
	ScoringModel string `json:"scoring_model,omitempty"`
	// SubScores are the per-group v2 sub-scores.
	SubScores []GroupScore `json:"sub_scores,omitempty"`
	// CapDriver is set only when a grade cap lowered Rating below the numeric band.
	CapDriver *CapDriver `json:"cap_driver,omitempty"`
	// NotAssessed are findings whose checks could not run (excluded from scoring).
	NotAssessed []Finding `json:"not_assessed,omitempty"`
}

// Fails returns only the findings that represent problems.
func (r *Result) Fails() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.IsFail() {
			out = append(out, f)
		}
	}
	return out
}
