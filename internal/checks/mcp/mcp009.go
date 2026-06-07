// Package mcp — MCP009: Known-CVE MCP tooling (heuristic).
//
// CVE-2025-49596: MCP Inspector allows arbitrary remote code execution via
// its web interface. It should never run in a persistent/always-on setup.
package mcp

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&mcp009{}) }

type mcp009 struct{}

func (c *mcp009) ID() string              { return "MCP009" }
func (c *mcp009) Title() string           { return catalog.Get("MCP009").Title }
func (c *mcp009) Group() model.CheckGroup { return catalog.Get("MCP009").Group }

// knownCVEMarkers are substrings that identify packages with known critical CVEs.
// Each entry carries the CVE ID for the finding Evidence field.
var knownCVEMarkers = []struct {
	marker string
	cveID  string
	detail string
}{
	{
		marker: "@modelcontextprotocol/inspector",
		cveID:  "CVE-2025-49596",
		detail: "MCP Inspector web UI allows arbitrary remote code execution when accessible from a browser",
	},
	{
		marker: "mcp-inspector",
		cveID:  "CVE-2025-49596",
		detail: "MCP Inspector web UI allows arbitrary remote code execution when accessible from a browser",
	},
}

func (c *mcp009) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("MCP009", "inside-out collector not available")}
	}
	sigs := ctx.Collector
	if len(sigs.Processes) == 0 && len(sigs.Configs) == 0 {
		return []model.Finding{notAssessed("MCP009", "no process or config data collected")}
	}

	type hit struct {
		resource string
		evidence string
	}
	var hits []hit

	// Check running processes.
	for _, proc := range sigs.Processes {
		argStr := strings.Join(proc.Args, " ")
		for _, m := range knownCVEMarkers {
			if strings.Contains(argStr, m.marker) || strings.Contains(proc.Comm, m.marker) {
				hits = append(hits, hit{
					resource: fmt.Sprintf("process %s (pid %d)", proc.Comm, proc.PID),
					evidence: fmt.Sprintf("%s (%s): %s", m.cveID, m.marker, m.detail),
				})
				break
			}
		}
	}

	// Check configured MCP server args.
	for _, cf := range sigs.Configs {
		if !cf.SchemaKnown {
			continue
		}
		for k, v := range cf.Values {
			if !strings.HasPrefix(k, "mcpServers.") {
				continue
			}
			for _, m := range knownCVEMarkers {
				if strings.Contains(v, m.marker) {
					hits = append(hits, hit{
						resource: fmt.Sprintf("%s (key %s)", cf.Source, k),
						evidence: fmt.Sprintf("%s (%s): %s", m.cveID, m.marker, m.detail),
					})
					break
				}
			}
		}
	}

	if len(hits) == 0 {
		return []model.Finding{catalog.Get("MCP009").Pass("No known-CVE MCP tooling detected.")}
	}

	var findings []model.Finding
	for _, h := range hits {
		f := catalog.Get("MCP009").Finding()
		f.Resource = h.resource
		f.Evidence = h.evidence
		f.ExposureClass = model.ExposureLocalhost
		f.Confidence = model.ConfidenceMedium
		f.Fix = model.Fix{
			Summary: "Remove MCP Inspector from persistent configs and running processes. Use it only interactively during development, never as a background service.",
			DocURL:  "https://github.com/advisories/GHSA-vc6f-5w6p-v2xq",
		}
		findings = append(findings, f)
	}
	return findings
}
