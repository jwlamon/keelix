// Package mcp — MCP004: HTTP/SSE MCP server bound non-loopback with no auth.
package mcp

import (
	"fmt"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&mcp004{}) }

type mcp004 struct{}

func (c *mcp004) ID() string              { return "MCP004" }
func (c *mcp004) Title() string           { return catalog.Get("MCP004").Title }
func (c *mcp004) Group() model.CheckGroup { return catalog.Get("MCP004").Group }

func (c *mcp004) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("MCP004", "inside-out collector not available")}
	}
	sigs := ctx.Collector
	if len(sigs.Sockets) == 0 {
		return []model.Finding{notAssessed("MCP004", "no socket data collected")}
	}

	// Build a PID→ProcessFact map for quick lookup.
	pidMap := make(map[int]model.ProcessFact, len(sigs.Processes))
	for _, p := range sigs.Processes {
		pidMap[p.PID] = p
	}

	var findings []model.Finding
	for _, sock := range sigs.Sockets {
		if isLoopback(sock.Bind) {
			continue
		}
		// Is the owning process an MCP-style server?
		if !isMCPServerComm(sock.Comm) {
			// Check the full process args for MCP signatures.
			proc, ok := pidMap[sock.PID]
			if !ok {
				continue
			}
			argStr := strings.Join(proc.Args, " ")
			if !strings.Contains(strings.ToLower(argStr), "mcp") &&
				!strings.Contains(strings.ToLower(argStr), "model-context-protocol") {
				continue
			}
		}

		f := catalog.Get("MCP004").Finding()
		f.Resource = fmt.Sprintf("port %d (pid %d, %s) bind=%s", sock.Port, sock.PID, sock.Comm, sock.Bind)
		f.Evidence = fmt.Sprintf("MCP server process %q (pid %d) listening on %s:%d — non-loopback bind with no observed authentication", sock.Comm, sock.PID, sock.Bind, sock.Port)
		f.ExposureClass = exposureFromBind(sock.Bind)
		f.Confidence = model.ConfidenceHigh
		f.Fix = model.Fix{
			Summary:  "Bind the MCP HTTP/SSE server to 127.0.0.1 only. If remote access is required, protect it with a reverse proxy and authentication.",
			Commands: []string{fmt.Sprintf("# Reconfigure the MCP server to bind 127.0.0.1:%d instead of %s:%d", sock.Port, sock.Bind, sock.Port)},
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP004").Pass("No MCP HTTP/SSE servers found listening on non-loopback addresses.")}
	}
	return findings
}
