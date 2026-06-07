package model

import "sort"

// CheckGroup is one of the deterministic check-library groups.
type CheckGroup string

const (
	GroupHost        CheckGroup = "Host OS"
	GroupExposure    CheckGroup = "Network Exposure"
	GroupFirewall    CheckGroup = "Docker/Firewall Bypass"
	GroupProxy       CheckGroup = "Reverse Proxy"
	GroupHardening   CheckGroup = "Container Hardening"
	GroupSecrets     CheckGroup = "Secrets"
	GroupTLS         CheckGroup = "TLS/Certificates"
	GroupDNS         CheckGroup = "DNS"
	GroupAuth        CheckGroup = "Authentication/Access"
	GroupSupplyChain CheckGroup = "Supply Chain"
	GroupService     CheckGroup = "Service Configuration"
	GroupAIAgent     CheckGroup = "AI Agent Posture"
	GroupMCP         CheckGroup = "MCP Posture"
)

// GroupOrder is the canonical display order of check groups in reports.
var GroupOrder = []CheckGroup{
	GroupHost,
	GroupExposure,
	GroupFirewall,
	GroupProxy,
	GroupHardening,
	GroupSecrets,
	GroupTLS,
	GroupDNS,
	GroupAuth,
	GroupSupplyChain,
	GroupService,
	GroupAIAgent,
	GroupMCP,
}

// Check is a single deterministic security check. Implementations MUST be pure
// functions of the ScanContext (no I/O, no globals, no time-of-day dependence
// beyond what is in the context) so results are reproducible and testable.
//
// A check returns one or more Findings. It SHOULD emit a passing Finding
// (SeverityOK, Passed=true) when it ran and found nothing wrong, so the report
// can show coverage. It returns nil only when the check is not applicable to the
// given stack (e.g. no reverse proxy present).
type Check interface {
	// ID is the stable unique identifier, e.g. "EXP001".
	ID() string
	// Title is a short human description of what the check verifies.
	Title() string
	// Group is the check-library group.
	Group() CheckGroup
	// Run evaluates the check against the scan context.
	Run(ctx *ScanContext) []Finding
}

// registry holds all checks registered via Register (typically from package
// init() functions blank-imported by internal/checks/all).
var registry = map[string]Check{}

// Register adds a check to the global registry. Duplicate IDs panic, surfacing
// programmer error at startup rather than silently dropping a check.
func Register(c Check) {
	id := c.ID()
	if _, exists := registry[id]; exists {
		panic("duplicate check ID registered: " + id)
	}
	registry[id] = c
}

// Registered returns all registered checks sorted by ID for deterministic order.
func Registered() []Check {
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
