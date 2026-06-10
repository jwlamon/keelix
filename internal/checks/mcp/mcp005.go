// Package mcp — MCP005: Localhost HTTP/SSE MCP server on potentially vulnerable SDK.
package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&mcp005{}) }

type mcp005 struct{}

func (c *mcp005) ID() string              { return "MCP005" }
func (c *mcp005) Title() string           { return catalog.Get("MCP005").Title }
func (c *mcp005) Group() model.CheckGroup { return catalog.Get("MCP005").Group }

// mcpServerNamesHTTP returns sorted unique MCP server names from a ConfigFact's
// Values by scanning keys matching "mcpServers.<name>.command" OR
// "mcpServers.<name>.type". The latter catches HTTP/SSE-only entries that omit
// the command field.
func mcpServerNamesHTTP(values map[string]string) []string {
	seen := map[string]struct{}{}
	for k := range values {
		if !strings.HasPrefix(k, "mcpServers.") {
			continue
		}
		rest := strings.TrimPrefix(k, "mcpServers.")
		dot := strings.Index(rest, ".")
		if dot < 0 {
			continue
		}
		suffix := rest[dot+1:]
		if suffix != "command" && suffix != "type" {
			continue
		}
		name := rest[:dot]
		if strings.Contains(name, ".") {
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

func (c *mcp005) Run(ctx *model.ScanContext) []model.Finding {
	cfgs := allMCPConfigs(ctx.Collector)
	if len(cfgs) == 0 {
		return []model.Finding{notAssessed("MCP005", "no MCP config files collected")}
	}

	var findings []model.Finding
	for _, cf := range cfgs {
		names := mcpServerNamesHTTP(cf.Values)
		for _, name := range names {
			typ := cf.Values[fmt.Sprintf("mcpServers.%s.type", name)]
			if typ != "http" && typ != "sse" {
				continue
			}
			rawURL := cf.Values[fmt.Sprintf("mcpServers.%s.url", name)]
			// SP1a: flag all localhost http/sse MCP entries; SDK-version refinement is pending (SP1b).
			// Only flag if URL suggests loopback (or no URL — type alone is enough).
			if rawURL != "" && !strings.Contains(rawURL, "127.0.0.1") &&
				!strings.Contains(rawURL, "localhost") && !strings.Contains(rawURL, "::1") {
				continue
			}

			f := catalog.Get("MCP005").Finding()
			f.Resource = fmt.Sprintf("mcpServers.%s (%s)", name, cf.Source)
			f.Evidence = fmt.Sprintf("type=%q url=%q — localhost HTTP/SSE MCP transport may use a vulnerable SDK version; SDK-version refinement is pending (SP1b)", typ, rawURL)
			f.ExposureClass = model.ExposureLocalhost
			f.Confidence = model.ConfidenceMedium
			f.Fix = model.Fix{
				Summary: "Update the MCP SDK to python-sdk >= 1.23.0 or TypeScript SDK >= 1.24.0 to remediate known vulnerabilities in the HTTP/SSE transport.",
				DocURL:  "https://github.com/modelcontextprotocol/python-sdk/releases",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP005").Pass("No localhost HTTP/SSE MCP transport entries detected.")}
	}
	return findings
}
