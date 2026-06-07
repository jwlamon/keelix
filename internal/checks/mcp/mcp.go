// Package mcp implements MCP-posture checks (MCP001–MCP009).
package mcp

import (
	"sort"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

// notAssessed returns a StatusNotAssessed finding for the given catalog ID.
// Used when ctx.Collector is nil or the required ConfigFact is absent.
func notAssessed(id, detail string) model.Finding {
	e := catalog.Get(id)
	f := e.Finding()
	f.Status = model.StatusNotAssessed
	if detail != "" {
		f.Detail = detail
	}
	return f
}

// configBySchema returns the first ConfigFact whose SchemaID matches, or false.
func configBySchema(sigs *model.Signals, schemaID string) (model.ConfigFact, bool) {
	if sigs == nil {
		return model.ConfigFact{}, false
	}
	for _, cf := range sigs.Configs {
		if cf.SchemaID == schemaID && cf.SchemaKnown {
			return cf, true
		}
	}
	return model.ConfigFact{}, false
}

// mcpServerNames returns the sorted unique MCP server names from a ConfigFact's
// Values by scanning keys matching "mcpServers.<name>.command".
func mcpServerNames(values map[string]string) []string {
	seen := map[string]struct{}{}
	for k := range values {
		// key must be "mcpServers.<name>.command"
		if !strings.HasPrefix(k, "mcpServers.") || !strings.HasSuffix(k, ".command") {
			continue
		}
		rest := strings.TrimPrefix(k, "mcpServers.")
		name := strings.TrimSuffix(rest, ".command")
		if strings.Contains(name, ".") {
			// nested — not a direct server name
			continue
		}
		seen[name] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// allMCPConfigs returns all ConfigFacts that contain MCP server definitions,
// identified by having at least one key with the "mcpServers." prefix.
func allMCPConfigs(sigs *model.Signals) []model.ConfigFact {
	if sigs == nil {
		return nil
	}
	var out []model.ConfigFact
	for _, cf := range sigs.Configs {
		if !cf.SchemaKnown {
			continue
		}
		for k := range cf.Values {
			if strings.HasPrefix(k, "mcpServers.") {
				out = append(out, cf)
				break
			}
		}
	}
	return out
}

// isLoopback reports whether a bind address is loopback-only.
func isLoopback(bind string) bool {
	return bind == "127.0.0.1" || bind == "::1" || bind == "localhost"
}

// exposureFromBind maps a socket bind address to a model.ExposureClass.
func exposureFromBind(bind string) model.ExposureClass {
	if isLoopback(bind) {
		return model.ExposureLocalhost
	}
	if strings.HasPrefix(bind, "10.") ||
		strings.HasPrefix(bind, "172.") ||
		strings.HasPrefix(bind, "192.168.") {
		return model.ExposureLAN
	}
	if strings.HasPrefix(bind, "100.") {
		return model.ExposureOverlay
	}
	return model.ExposureInternet
}

// isMCPServerComm reports whether a process comm string looks like an MCP server.
// Heuristic: npx, uvx, pipx, node, python, python3, deno, bun running a server.
func isMCPServerComm(comm string) bool {
	lower := strings.ToLower(comm)
	for _, pfx := range []string{"npx", "uvx", "pipx", "node", "python", "python3", "deno", "bun"} {
		if lower == pfx || strings.HasPrefix(lower, pfx) {
			return true
		}
	}
	return false
}
