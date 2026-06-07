package collect

import (
	"encoding/json"
	"fmt"
	"strings"
)

// flattenJSON unmarshals a JSON object and flattens it to dotted string keys.
// Arrays use numeric segments (key.0, key.1). Booleans and numbers are
// stringified ("true"/"false"/"42"). Null values are skipped. Returns
// ok=false if the input is not a valid JSON object.
func flattenJSON(b []byte) (map[string]string, bool) {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, false
	}
	out := make(map[string]string)
	flattenInto(out, "", raw)
	return out, true
}

// flattenInto recursively walks v, writing leaf values into dst under the given
// prefix. A prefix of "" means top-level (keys are not prefixed with a dot).
func flattenInto(dst map[string]string, prefix string, v any) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			flattenInto(dst, key, child)
		}
	case []any:
		for i, child := range val {
			key := fmt.Sprintf("%s.%d", prefix, i)
			flattenInto(dst, key, child)
		}
	case string:
		dst[prefix] = val
	case bool:
		if val {
			dst[prefix] = "true"
		} else {
			dst[prefix] = "false"
		}
	case float64:
		// json.Unmarshal decodes all numbers as float64.
		// Use integer formatting when the value is a whole number.
		if val == float64(int64(val)) {
			dst[prefix] = fmt.Sprintf("%d", int64(val))
		} else {
			dst[prefix] = fmt.Sprintf("%g", val)
		}
	case nil:
		// skip null values
	default:
		dst[prefix] = fmt.Sprintf("%v", val)
	}
}

// mcpServerNames returns sorted unique MCP server names found in a flattened
// config map by matching keys of the form "mcpServers.<name>.command".
func mcpServerNames(values map[string]string) []string {
	seen := map[string]struct{}{}
	for k := range values {
		// Must match exactly: "mcpServers.<name>.command"
		if !strings.HasPrefix(k, "mcpServers.") {
			continue
		}
		rest := k[len("mcpServers."):]
		dot := strings.Index(rest, ".")
		if dot < 0 {
			continue
		}
		if rest[dot+1:] != "command" {
			continue
		}
		name := rest[:dot]
		seen[name] = struct{}{}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	// Sort for determinism.
	sortStrings(names)
	return names
}

// sortStrings sorts a string slice in place (insertion sort — slices are small).
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}
