// Package mcp — MCP003: Unpinned npx/uvx/pipx "latest" MCP server.
package mcp

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&mcp003{}) }

type mcp003 struct{}

func (c *mcp003) ID() string              { return "MCP003" }
func (c *mcp003) Title() string           { return catalog.Get("MCP003").Title }
func (c *mcp003) Group() model.CheckGroup { return catalog.Get("MCP003").Group }

// unpinnedRunners are package managers whose auto-fetch behaviour is unsafe without a pin.
var unpinnedRunners = map[string]bool{"npx": true, "uvx": true, "pipx": true}

func (c *mcp003) Run(ctx *model.ScanContext) []model.Finding {
	cfgs := allMCPConfigs(ctx.Collector)
	if len(cfgs) == 0 {
		return []model.Finding{notAssessed("MCP003", "no MCP config files collected")}
	}

	var findings []model.Finding
	for _, cf := range cfgs {
		names := mcpServerNames(cf.Values)
		for _, name := range names {
			cmd := cf.Values[fmt.Sprintf("mcpServers.%s.command", name)]
			if !unpinnedRunners[strings.ToLower(cmd)] {
				continue
			}

			// Gather all args for this server.
			var args []string
			for i := 0; ; i++ {
				v, ok := cf.Values[fmt.Sprintf("mcpServers.%s.args.%d", name, i)]
				if !ok {
					break
				}
				args = append(args, v)
			}

			// Check for auto-install flags without a version pin.
			hasAutoFlag := false
			hasPinToken := false
			for _, arg := range args {
				if arg == "-y" || arg == "--yes" {
					hasAutoFlag = true
				}
				// A version pin for npm packages is "@<semver>" appearing after the
				// first character (e.g. "pkg@1.2.3" or "@scope/pkg@1.2.3").
				// A scoped package like "@scope/pkg" has @ only at position 0 — not a pin.
				// For uvx/pipx, "==" is the version separator.
				if (len(arg) > 1 && strings.Contains(arg[1:], "@")) || strings.Contains(arg, "==") {
					hasPinToken = true
				}
			}

			if !hasAutoFlag || hasPinToken {
				continue
			}

			f := catalog.Get("MCP003").Finding()
			f.Resource = fmt.Sprintf("mcpServers.%s (%s)", name, cf.Source)
			f.Evidence = fmt.Sprintf("command=%q args=%v — uses auto-install flag without a version pin", cmd, args)
			f.ExposureClass = model.ExposureLocalhost
			f.Confidence = model.ConfidenceHigh
			f.Fix = model.Fix{
				Summary: fmt.Sprintf("Pin the package to an explicit version, e.g. %s -y package@1.2.3 (npm) or package==1.2.3 (PyPI).", cmd),
			}
			findings = append(findings, f)
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP003").Pass("All npx/uvx/pipx MCP servers are pinned to explicit versions.")}
	}
	return findings
}
