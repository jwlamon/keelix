// Package aiagent implements GroupAIAgent checks (AGT001–AGT010).
// All checks are pure functions of *model.ScanContext: no I/O, no globals,
// no time.Now(). The only data source is ctx.Collector (*model.Signals).
package aiagent

import (
	"sort"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

// NotAssessed returns a finding for the given catalog ID with
// Status=StatusNotAssessed. Use this when the required ConfigFact or
// ctx.Collector is absent so the check cannot make a determination.
func NotAssessed(id string) model.Finding {
	f := catalog.Get(id).Finding()
	f.Status = model.StatusNotAssessed
	f.Detail = "inside-out collector data unavailable for this check; run with --collect"
	return f
}

// ConfigBySchema returns the first ConfigFact in sigs.Configs whose SchemaID
// matches id and whose SchemaKnown is true. ok is false when no match exists.
func ConfigBySchema(sigs *model.Signals, id string) (model.ConfigFact, bool) {
	if sigs == nil {
		return model.ConfigFact{}, false
	}
	for _, c := range sigs.Configs {
		if c.SchemaID == id && c.SchemaKnown {
			return c, true
		}
	}
	return model.ConfigFact{}, false
}

// McpServerNames returns the sorted unique server <name> values extracted from
// keys matching the pattern "mcpServers.<name>.command" in the given flat
// values map. This is the agreed enumeration pattern for the flat ConfigFact
// map[string]string shape.
func McpServerNames(values map[string]string) []string {
	seen := map[string]struct{}{}
	for k := range values {
		if !strings.HasPrefix(k, "mcpServers.") {
			continue
		}
		rest := k[len("mcpServers."):]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			continue
		}
		suffix := rest[dot+1:]
		if suffix != "command" {
			continue
		}
		seen[rest[:dot]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// exposureFromBind derives an ExposureClass from a socket's Bind address.
// 127.0.0.1 and ::1 are Localhost; everything else is LAN (private RFC1918)
// or Internet — we conservatively return ExposureLAN for any non-loopback
// non-overlay address and ExposureInternet for 0.0.0.0/::.
func exposureFromBind(bind string) model.ExposureClass {
	switch bind {
	case "127.0.0.1", "::1":
		return model.ExposureLocalhost
	case "0.0.0.0", "::":
		return model.ExposureInternet
	default:
		return model.ExposureLAN
	}
}
