// Package mcp — MCP007: Tool-poisoning / rug-pull drift (active probe, SP1b).
//
// When the active MCP probe ran (Signals.MCPProbe != nil), MCP007 inspects every
// tool advertised by every reached server. A tool whose description hash changed
// since the recorded baseline (MCPToolFact.Drifted) while the server identity is
// unchanged is the signature of a rug-pull / tool-poisoning attack and is emitted
// as a Critical finding. When the probe ran but only recorded new tools
// (FirstSeen, no drift) the check passes with an inventory note. When the probe
// did not run (MCPProbe == nil), the check is NotAssessed.
package mcp

import (
	"fmt"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&mcp007{}) }

type mcp007 struct{}

func (c *mcp007) ID() string              { return "MCP007" }
func (c *mcp007) Title() string           { return catalog.Get("MCP007").Title }
func (c *mcp007) Group() model.CheckGroup { return catalog.Get("MCP007").Group }

func (c *mcp007) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil || ctx.Collector.MCPProbe == nil {
		return []model.Finding{notAssessed("MCP007",
			"active MCP probe disabled (run with --probe-mcp; SP1b)")}
	}

	// SBX-9(b): corrupt baseline means drift detection is impaired — all tools
	// appeared as FirstSeen instead of being compared against stored hashes.
	// Emit a Critical finding so the operator knows to re-baseline.
	if ctx.Collector.MCPProbe.CorruptBaseline {
		f := catalog.Get("MCP007").Finding()
		f.Detail = "The MCP tool baseline file is corrupt or was partially written. " +
			"Drift detection is impaired: all tools appear as first-seen rather than " +
			"being compared against the stored hashes. Re-run the probe to rebuild the " +
			"baseline, or delete ~/.keelix/mcp-baseline.json and re-scan."
		f.Evidence = "mcp-baseline.json: invalid JSON (corrupt or partial write)"
		f.ExposureClass = model.ExposureLocalhost
		f.Confidence = model.ConfidenceHigh
		f.Fix = model.Fix{
			Summary:  "Delete or repair ~/.keelix/mcp-baseline.json and re-run the probe to rebuild a clean baseline.",
			Commands: []string{"rm ~/.keelix/mcp-baseline.json"},
		}
		return []model.Finding{f}
	}

	var findings []model.Finding
	inventoried := 0
	for _, srv := range ctx.Collector.MCPProbe.Servers {
		for _, tool := range srv.Tools {
			inventoried++
			if !tool.Drifted {
				continue
			}
			f := catalog.Get("MCP007").Finding() // Severity=Critical from the catalog
			f.Service = srv.Name
			f.Resource = fmt.Sprintf("mcpServers.%s tool %q", srv.Name, tool.Name)
			f.Evidence = fmt.Sprintf(
				"server %q tool %q description changed since baseline (server identity unchanged) — tool-poisoning/rug-pull drift",
				srv.Name, tool.Name)
			f.ExposureClass = model.ExposureLocalhost
			f.Confidence = model.ConfidenceHigh
			f.Fix = model.Fix{
				Summary: "Re-review the changed MCP tool. If the new description is legitimate, re-approve it to update the baseline; otherwise remove the server. A description change on an unchanged server is the rug-pull signature.",
				DocURL:  "https://modelcontextprotocol.io/docs/security",
			}
			findings = append(findings, f)
		}
	}

	if len(findings) > 0 {
		return findings
	}
	if inventoried == 0 {
		return []model.Finding{notAssessed("MCP007",
			"active MCP probe ran but reached no MCP tools")}
	}
	return []model.Finding{catalog.Get("MCP007").Pass(
		fmt.Sprintf("Active MCP probe recorded %d tool(s); no description drift versus the baseline.", inventoried))}
}
