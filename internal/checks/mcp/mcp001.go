// Package mcp — MCP001: Plaintext secret in MCP config.
package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&mcp001{}) }

type mcp001 struct{}

func (c *mcp001) ID() string              { return "MCP001" }
func (c *mcp001) Title() string           { return catalog.Get("MCP001").Title }
func (c *mcp001) Group() model.CheckGroup { return catalog.Get("MCP001").Group }

// mcp001ServerNames returns the sorted unique MCP server names derived from
// ANY mcpServers.<name>.* key in values — not only servers that have a .command
// key. This is intentionally broader than the shared mcpServerNames helper so
// that command-less remote servers (http/sse with only url/type) are included.
func mcp001ServerNames(values map[string]string) []string {
	const prefix = "mcpServers."
	seen := map[string]struct{}{}
	for k := range values {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		// rest = "<name>.<field>"; extract <name> as everything up to first dot.
		dot := strings.IndexByte(rest, '.')
		if dot <= 0 {
			continue // no field separator or empty name
		}
		name := rest[:dot]
		seen[name] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (c *mcp001) Run(ctx *model.ScanContext) []model.Finding {
	cfgs := allMCPConfigs(ctx.Collector)
	if len(cfgs) == 0 {
		return []model.Finding{notAssessed("MCP001", "no MCP config files collected")}
	}

	var findings []model.Finding
	for _, cf := range cfgs {
		// Use mcp001ServerNames (not mcpServerNames) to enumerate ALL servers,
		// including command-less remote servers that only have url/type keys.
		names := mcp001ServerNames(cf.Values)
		for _, name := range names {
			// Check env.<KEY>, headers.<KEY>, and url for credential markers.
			for k, v := range cf.Values {
				if !strings.HasPrefix(k, fmt.Sprintf("mcpServers.%s.env.", name)) &&
					!strings.HasPrefix(k, fmt.Sprintf("mcpServers.%s.headers.", name)) &&
					k != fmt.Sprintf("mcpServers.%s.url", name) {
					continue
				}
				// "[keychain-ref]" is a POSITIVE CONTROL: the collector emits this
				// marker when the config value is a keychain URI (keychain:…),
				// 1Password reference (op://…), or shell-variable reference ($VAR).
				// These hold references, not raw secrets — do not flag them.
				if v == "[keychain-ref]" {
					continue
				}
				// "[secret]" is the collector's marker for a plaintext credential.
				// Any other non-marker value in a credential field was not redacted,
				// meaning the collector did not detect it as a secret — skip it here
				// (it is not a confirmed plaintext secret in the context of this check).
				if v != "[secret]" {
					continue
				}
				f := catalog.Get("MCP001").Finding()
				f.Resource = fmt.Sprintf("mcpServers.%s (%s)", name, cf.Source)
				f.Evidence = fmt.Sprintf("key %q has value \"[secret]\" — a secret was present in plaintext and redacted by the collector", k)
				f.ExposureClass = model.ExposureLocalhost
				f.Confidence = model.ConfidenceHigh
				f.Fix = model.Fix{
					Summary: "Store secrets in a system keychain (e.g. macOS Keychain, Linux Secret Service) and reference them by keychain URI rather than embedding them in the config file.",
					DocURL:  "https://modelcontextprotocol.io/docs/security",
				}
				findings = append(findings, f)
			}
		}
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP001").Pass("No plaintext secrets found in MCP config files.")}
	}
	return findings
}
