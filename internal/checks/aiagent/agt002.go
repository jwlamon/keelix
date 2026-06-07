package aiagent

import (
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&agt002{}) }

type agt002 struct{}

func (c *agt002) ID() string              { return catalog.Get("AGT002").ID }
func (c *agt002) Title() string           { return catalog.Get("AGT002").Title }
func (c *agt002) Group() model.CheckGroup { return catalog.Get("AGT002").Group }

// messagingServerNames are lower-case substrings that indicate a messaging/exfil MCP server.
var messagingServerNames = []string{"slack", "telegram", "gmail", "discord", "email", "mail", "smtp"}

// webServerNames are lower-case substrings indicating an untrusted-ingest MCP server.
var webServerNames = []string{"web", "browser", "fetch", "search", "http", "scrape", "crawl", "puppeteer", "playwright"}

// isMessagingServer returns true if the server name or command suggests a messaging/exfil capability.
func isMessagingServer(name, cmd string) bool {
	combined := strings.ToLower(name + " " + cmd)
	for _, kw := range messagingServerNames {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

// isMessagingURL returns true if the server URL suggests a messaging/exfil capability.
func isMessagingURL(url string) bool {
	lower := strings.ToLower(url)
	for _, kw := range messagingServerNames {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isWebServer returns true if the server name or command suggests untrusted-ingest capability.
func isWebServer(name, cmd string) bool {
	combined := strings.ToLower(name + " " + cmd)
	for _, kw := range webServerNames {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

// mcpAllServerNames returns all unique MCP server names found in the flat
// values map. Unlike the shared McpServerNames helper (which only enumerates
// servers with a ".command" key), this enumerates servers present via ANY
// mcpServers.<name>.* key — including remote HTTP/SSE servers that only have
// url/type/headers keys and no command.
func mcpAllServerNames(values map[string]string) []string {
	seen := map[string]struct{}{}
	prefix := "mcpServers."
	for k := range values {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := k[len(prefix):]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		seen[rest[:dot]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out
}

func (c *agt002) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{NotAssessed("AGT002")}
	}

	// Evaluate the three trifecta legs PER CONFIG (per agent instance).
	// All three legs must co-exist within a SINGLE ConfigFact to fire.
	// Legs from distinct agents/configs must NOT be combined — that would
	// produce false positives (RFX-4 Bug-1).
	for _, cfg := range ctx.Collector.Configs {
		if !cfg.SchemaKnown {
			continue
		}

		v := cfg.Values

		// Leg 1: private-data access.
		// OpenClaw tools.fs.workspaceOnly=="false" means unrestricted filesystem access.
		hasPrivateData := false
		if v["tools.fs.workspaceOnly"] == "false" {
			hasPrivateData = true
		}
		// Also flag if a Claude broad glob is present (AGT008 territory; also covers leg 1).
		for k, val := range v {
			if strings.HasPrefix(k, "permissions.allow.") && (val == "**" || val == "~/**") {
				hasPrivateData = true
			}
		}

		// Leg 2: untrusted-ingest capability.
		hasUntrustedIngest := false
		if v["browser.enabled"] == "true" {
			hasUntrustedIngest = true
		}
		if v["tools.web.search.provider"] != "" {
			hasUntrustedIngest = true
		}
		// MCP servers suggesting web/browser/fetch.
		for _, name := range McpServerNames(v) {
			cmd := v["mcpServers."+name+".command"]
			if isWebServer(name, cmd) {
				hasUntrustedIngest = true
			}
		}

		// Leg 3: exfil channel — messaging MCP server or outbound http MCP.
		// Use mcpAllServerNames to enumerate ALL servers, including command-less
		// remote HTTP/SSE servers that only have url/type keys (RFX-4 Bug-2).
		hasExfil := false
		for _, name := range mcpAllServerNames(v) {
			cmd := v["mcpServers."+name+".command"]
			url := v["mcpServers."+name+".url"]
			typ := strings.ToLower(v["mcpServers."+name+".type"])
			// Messaging server: name/command or URL indicates a messaging platform.
			if isMessagingServer(name, cmd) || isMessagingURL(url) {
				hasExfil = true
			}
			// Generic remote HTTP/SSE server: any server reachable over http/sse
			// (i.e. not a local stdio process) is a potential outbound exfil channel.
			if (typ == "http" || typ == "sse") && url != "" {
				hasExfil = true
			}
		}

		if hasPrivateData && hasUntrustedIngest && hasExfil {
			f := catalog.Get("AGT002").Finding()
			f.ExposureClass = model.ExposureLocalhost
			f.Confidence = model.ConfidenceMedium
			f.Resource = "agent capability combination"
			f.Evidence = "private-data access + untrusted-ingest capability + exfil channel all co-present in one agent"
			f.Metadata = map[string]string{"capability_proxy": "true"}
			f.Fix = model.Fix{
				Summary: "Remove at least one leg: restrict filesystem access (fs.workspaceOnly=true), disable browser/web search, or remove messaging MCP servers.",
			}
			return []model.Finding{f}
		}
	}

	return []model.Finding{catalog.Get("AGT002").Pass("Lethal-trifecta capability co-presence not detected.")}
}
