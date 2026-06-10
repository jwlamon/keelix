package engine

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jakelamon/keelix/internal/mcpprobe"
	"github.com/jakelamon/keelix/internal/model"
)

// deriveServerSpecs turns collected MCP config facts into probe specs. It mirrors
// the mcpServerNames pattern used by the MCP checks: a server is any
// "mcpServers.<name>.command" (stdio) OR "mcpServers.<name>.url"/".type" (remote)
// key. stdio servers carry Command/Args/EnvKeys; remote servers carry URL.
//
// Pure: no I/O, deterministic ordering (servers sorted by name, args by index).
func deriveServerSpecs(sig *model.Signals) []mcpprobe.ServerSpec {
	if sig == nil || len(sig.Configs) == 0 {
		return nil
	}
	var specs []mcpprobe.ServerSpec
	for _, cf := range sig.Configs {
		if !cf.SchemaKnown {
			continue
		}
		for _, name := range serverNamesFromValues(cf.Values) {
			spec := mcpprobe.ServerSpec{Name: name, Client: cf.Source}
			cmd := cf.Values[fmt.Sprintf("mcpServers.%s.command", name)]
			url := cf.Values[fmt.Sprintf("mcpServers.%s.url", name)]
			typ := cf.Values[fmt.Sprintf("mcpServers.%s.type", name)]
			switch {
			case cmd != "":
				spec.Transport = "stdio"
				spec.Command = cmd
				spec.Args = orderedArgs(cf.Values, name)
				spec.EnvKeys = envKeys(cf.Values, name)
			case url != "" || typ == "http" || typ == "sse":
				if typ == "sse" {
					spec.Transport = "sse"
				} else {
					spec.Transport = "http"
				}
				spec.URL = url
			default:
				continue // not a probeable server definition
			}
			specs = append(specs, spec)
		}
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	return specs
}

// serverNamesFromValues returns the sorted unique MCP server names referenced by
// a command, url, or type key under "mcpServers.<name>.".
func serverNamesFromValues(values map[string]string) []string {
	const prefix = "mcpServers."
	seen := map[string]struct{}{}
	for k := range values {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		dot := strings.IndexByte(rest, '.')
		if dot <= 0 {
			continue
		}
		name := rest[:dot]
		suffix := rest[dot+1:]
		if suffix == "command" || suffix == "url" || suffix == "type" {
			seen[name] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// orderedArgs reconstructs the args slice from "mcpServers.<name>.args.<i>"
// keys, ordered by integer index.
func orderedArgs(values map[string]string, name string) []string {
	prefix := fmt.Sprintf("mcpServers.%s.args.", name)
	idx := map[int]string{}
	max := -1
	for k, v := range values {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(k, prefix))
		if err != nil {
			continue
		}
		idx[n] = v
		if n > max {
			max = n
		}
	}
	if max < 0 {
		return nil
	}
	out := make([]string, 0, max+1)
	for i := 0; i <= max; i++ {
		if v, ok := idx[i]; ok {
			out = append(out, v)
		}
	}
	return out
}

// envKeys returns env entries for a server. Named keys (e.g. "TOKEN") are
// returned as-is so the probe can resolve their values from the host
// environment via os.Getenv. Integer-indexed keys (e.g. "0", "1") follow the
// Docker compose convention where the VALUE is a literal "KEY=VALUE" string;
// in that case the VALUE is returned rather than the index, letting the probe
// inject it directly without a host-env lookup.
func envKeys(values map[string]string, name string) []string {
	prefix := fmt.Sprintf("mcpServers.%s.env.", name)
	var keys []string
	for k, v := range values {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(k, prefix)
		if _, err := strconv.Atoi(suffix); err == nil {
			// Integer-indexed: the value is a literal "KEY=VALUE" env entry.
			keys = append(keys, v)
		} else {
			// Named key: the name itself is the env var name; the probe resolves
			// the value via os.Getenv(suffix).
			keys = append(keys, suffix)
		}
	}
	sort.Strings(keys)
	return keys
}

// formatPlannedCommands renders each spec as a single human-readable line for
// the consent prompt: stdio servers show "<command> <args...>", remote servers
// show their URL. Order follows deriveServerSpecs (sorted by name).
func formatPlannedCommands(specs []mcpprobe.ServerSpec) []string {
	out := make([]string, 0, len(specs))
	for _, sp := range specs {
		if sp.Transport == "stdio" {
			line := sp.Command
			if len(sp.Args) > 0 {
				line += " " + strings.Join(sp.Args, " ")
			}
			out = append(out, fmt.Sprintf("%s (stdio): %s", sp.Name, line))
		} else {
			out = append(out, fmt.Sprintf("%s (%s): %s", sp.Name, sp.Transport, sp.URL))
		}
	}
	return out
}

// PlannedMCPProbeCommands returns the human-readable command lines the active
// probe would execute for the given Input, by loading/collecting the same
// signals the scan will use. It is used by the CLI consent prompt so the
// operator sees the EXACT commands before consenting. Best-effort: on any
// collection error it returns whatever specs could be derived (possibly empty).
func PlannedMCPProbeCommands(in Input) []string {
	sig := collectForPlanning(in)
	return formatPlannedCommands(deriveServerSpecs(sig))
}
