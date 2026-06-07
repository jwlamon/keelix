package mcpprobe

import (
	"encoding/json"
	"fmt"
)

// maxToolPages bounds tools/list pagination so a hostile server cannot make us
// loop forever following nextCursor.
const maxToolPages = 64

// discoveredTool is a tool name+description collected from a server.
type discoveredTool struct {
	Name        string
	Description string
}

// MCPClient runs the MCP handshake over a Transport and lists tools. It holds
// no host state; the untrusted child (if any) lives behind the Transport.
type MCPClient struct {
	t Transport
}

func newClient(t Transport) *MCPClient { return &MCPClient{t: t} }

// discover performs initialize -> validate protocolVersion -> initialized ->
// tools/list (paginated, capped) and returns the collected tools.
func (c *MCPClient) discover() ([]discoveredTool, error) {
	// 1. initialize
	initParams := map[string]any{
		"protocolVersion": supportedProtocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "keelix", "version": clientVersion},
	}
	raw, err := c.t.Send("initialize", initParams)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var initRes struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(raw, &initRes); err != nil {
		return nil, fmt.Errorf("initialize result: %w", err)
	}
	if !protocolSupported(initRes.ProtocolVersion) {
		return nil, fmt.Errorf("unsupported protocolVersion %q", initRes.ProtocolVersion)
	}

	// 2. notifications/initialized (no reply expected)
	if err := c.t.notify("notifications/initialized", map[string]any{}); err != nil {
		return nil, fmt.Errorf("initialized notify: %w", err)
	}

	// 3. tools/list with bounded nextCursor pagination
	var tools []discoveredTool
	cursor := ""
	for page := 0; page < maxToolPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		lraw, err := c.t.Send("tools/list", params)
		if err != nil {
			return nil, fmt.Errorf("tools/list: %w", err)
		}
		var lr struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(lraw, &lr); err != nil {
			return nil, fmt.Errorf("tools/list result: %w", err)
		}
		for _, tl := range lr.Tools {
			tools = append(tools, discoveredTool{Name: tl.Name, Description: tl.Description})
		}
		if lr.NextCursor == "" {
			break
		}
		cursor = lr.NextCursor
	}
	return tools, nil
}

// clientVersion is reported in clientInfo during initialize.
const clientVersion = "0.1.0"
