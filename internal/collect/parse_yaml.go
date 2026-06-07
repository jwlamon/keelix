package collect

import (
	"strings"
)

// parseYAML parses a simple YAML document (nested mappings only) into a flat
// dotted-key map. Lists and anchors are intentionally unsupported — SP3 targets
// only use simple nested scalar mappings. Indentation is measured in leading
// spaces; tabs are treated as 4 spaces. Comments (#) and blank lines are
// skipped. Values are string-ified: booleans and numbers pass through verbatim.
func parseYAML(b []byte) map[string]string {
	out := make(map[string]string)
	// keyStack holds (indent, key-segment) pairs.
	type frame struct {
		indent int
		key    string
	}
	var stack []frame

	lines := splitLines(string(b))
	for _, raw := range lines {
		// Expand tabs → 4 spaces for indent measurement.
		expanded := strings.ReplaceAll(raw, "\t", "    ")
		indent := 0
		for _, ch := range expanded {
			if ch == ' ' {
				indent++
			} else {
				break
			}
		}
		line := trimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		// Unwind stack to current indent level.
		for len(stack) > 0 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		// Parse "key: value" or "key:".
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := trimSpace(line[:colon])
		val := trimSpace(line[colon+1:])
		// Strip inline comment.  Two cases:
		// 1. "key: value # comment" — strip at the space-hash boundary.
		// 2. "key: # comment"       — value starts with '#', treat as empty.
		if strings.HasPrefix(val, "#") {
			val = ""
		} else if ci := strings.Index(val, " #"); ci >= 0 {
			val = trimSpace(val[:ci])
		}
		// Build full key.
		prefix := ""
		for _, f := range stack {
			if prefix == "" {
				prefix = f.key
			} else {
				prefix = prefix + "." + f.key
			}
		}
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		if val == "" {
			// Mapping node — push onto stack.
			stack = append(stack, frame{indent: indent, key: key})
			continue
		}
		// Strip surrounding quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		out[fullKey] = val
	}
	return out
}
