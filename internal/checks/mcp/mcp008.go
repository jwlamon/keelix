// Package mcp — MCP008: Permission-bypass amplifier.
package mcp

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&mcp008{}) }

type mcp008 struct{}

func (c *mcp008) ID() string              { return "MCP008" }
func (c *mcp008) Title() string           { return catalog.Get("MCP008").Title }
func (c *mcp008) Group() model.CheckGroup { return catalog.Get("MCP008").Group }

func (c *mcp008) Run(ctx *model.ScanContext) []model.Finding {
	cfgs := allMCPConfigs(ctx.Collector)
	if len(cfgs) == 0 {
		return []model.Finding{notAssessed("MCP008", "no MCP config files collected")}
	}

	type amplifier struct {
		key      string
		valMatch string // exact match; empty = any truthy value
		evidence string
	}

	// These amplifier keys appear in claude-json and claude-desktop-config shapes.
	amplifiers := []amplifier{
		{
			key:      "bypassPermissionsModeEnabled",
			valMatch: "true",
			evidence: "bypassPermissionsModeEnabled=true removes all permission prompts from the Claude client",
		},
		{
			key:      "preferences.bypassPermissionsModeEnabled",
			valMatch: "true",
			evidence: "preferences.bypassPermissionsModeEnabled=true removes all permission prompts from Claude Desktop",
		},
		{
			key:      "allowAllBrowserActions",
			valMatch: "true",
			evidence: "allowAllBrowserActions=true grants MCP servers unrestricted browser control",
		},
		{
			key:      "preferences.allowAllBrowserActions",
			valMatch: "true",
			evidence: "preferences.allowAllBrowserActions=true grants MCP servers unrestricted browser control",
		},
	}

	var findings []model.Finding
	for _, cf := range cfgs {
		for _, amp := range amplifiers {
			v, ok := cf.Values[amp.key]
			if !ok {
				continue
			}
			if amp.valMatch != "" && v != amp.valMatch {
				continue
			}
			f := catalog.Get("MCP008").Finding()
			f.Resource = cf.Source
			f.Evidence = amp.evidence
			f.ExposureClass = model.ExposureLocalhost
			f.Confidence = model.ConfidenceHigh
			f.Fix = model.Fix{
				Summary: "Remove the bypass/amplifier flag from the config. These settings disable safeguards that limit what MCP servers can do on your behalf.",
			}
			findings = append(findings, f)
		}

		// broad trustedFolders (any entry whose value is "/" or "~" or starts with "~/")
		for k, v := range cf.Values {
			if !strings.HasPrefix(k, "preferences.localAgentModeTrustedFolders.") {
				continue
			}
			if v == "/" || v == "~" || strings.HasPrefix(v, "~/") || v == "/Users" || v == "/home" {
				f := catalog.Get("MCP008").Finding()
				f.Resource = cf.Source
				f.Evidence = "preferences.localAgentModeTrustedFolders contains a broad path (" + v + ") — grants MCP local-agent mode over most of the filesystem"
				f.ExposureClass = model.ExposureLocalhost
				f.Confidence = model.ConfidenceHigh
				f.Fix = model.Fix{
					Summary: "Restrict localAgentModeTrustedFolders to specific project directories rather than broad paths like / or ~/.",
				}
				findings = append(findings, f)
				break // one finding per config per broad-path
			}
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP008").Pass("No permission-bypass amplifier flags detected in MCP configs.")}
	}
	return findings
}
