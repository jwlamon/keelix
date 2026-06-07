// Package mcp — MCP002: Weak MCP config file permissions.
package mcp

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

func init() { model.Register(&mcp002{}) }

type mcp002 struct{}

func (c *mcp002) ID() string              { return "MCP002" }
func (c *mcp002) Title() string           { return catalog.Get("MCP002").Title }
func (c *mcp002) Group() model.CheckGroup { return catalog.Get("MCP002").Group }

func (c *mcp002) Run(ctx *model.ScanContext) []model.Finding {
	cfgs := allMCPConfigs(ctx.Collector)
	if len(cfgs) == 0 {
		return []model.Finding{notAssessed("MCP002", "no MCP config files collected")}
	}

	var findings []model.Finding
	for _, cf := range cfgs {
		if cf.Mode == "" {
			continue
		}
		// Only flag if the file bears at least one secret marker.
		hasSecret := false
		for _, v := range cf.Values {
			if v == "[secret]" {
				hasSecret = true
				break
			}
		}
		if !hasSecret {
			continue
		}
		// Parse the octal mode string and check group/other bits.
		// Owner-only modes (0600, 0700) are safe; only flag when group/other bits are set.
		modeStr := strings.TrimLeft(cf.Mode, "0")
		if modeStr == "" {
			modeStr = "0"
		}
		modeVal, err := strconv.ParseInt(modeStr, 8, 64)
		if err != nil {
			continue
		}
		// 0077 masks all group and other bits. Zero means no group/world access.
		if modeVal&0077 == 0 {
			continue
		}
		f := catalog.Get("MCP002").Finding()
		f.Resource = cf.Source
		f.Evidence = fmt.Sprintf("file mode %s is more permissive than 0600 and the config contains secret-bearing MCP server entries", cf.Mode)
		f.ExposureClass = model.ExposureLocalhost
		f.Confidence = model.ConfidenceHigh
		f.Fix = model.Fix{
			Summary:  "Restrict the config file to owner-read-write only.",
			Commands: []string{fmt.Sprintf("chmod 0600 %s", cf.Source)},
		}
		findings = append(findings, f)
	}

	if len(findings) == 0 {
		return []model.Finding{catalog.Get("MCP002").Pass("MCP config file permissions are suitably restrictive.")}
	}
	return findings
}
