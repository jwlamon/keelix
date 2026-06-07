package model

// ScoreDomain groups CheckGroups into broad scoring domains. The v2 score
// engine uses DomainOf to apply domain-specific cap rules (e.g. the autonomy
// RED cap for AI/MCP findings).
type ScoreDomain string

const (
	// DomainBox covers all traditional infrastructure security groups.
	DomainBox ScoreDomain = "box"
	// DomainAIMCP covers the AI agent and MCP posture groups introduced in SP1a.
	DomainAIMCP ScoreDomain = "ai-mcp"
)

// DomainOf returns the ScoreDomain for a given CheckGroup. GroupAIAgent and
// GroupMCP belong to DomainAIMCP; all other groups (including any future groups
// not yet listed) default to DomainBox.
func DomainOf(g CheckGroup) ScoreDomain {
	switch g {
	case GroupAIAgent, GroupMCP:
		return DomainAIMCP
	default:
		return DomainBox
	}
}
