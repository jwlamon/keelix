package collect

import "strings"

// parseINI parses an INI/conf-style file into a flat map.
// Section headers "[section]" prefix keys as "section.key".
// Top-level keys (before any section) are stored without prefix.
// Both "key=value" and "key value" (space-separated) forms are accepted.
// Lines beginning with "#", ";", or blank lines are skipped.
// Inline comments (# or ;) on value lines are stripped.
func parseINI(b []byte) map[string]string {
	out := make(map[string]string)
	section := ""
	for _, raw := range splitLines(string(b)) {
		line := trimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Section header.
		if line[0] == '[' {
			end := indexByte(line, ']')
			if end > 1 {
				// Lowercase section names so [Security] and [security] resolve
				// to the same prefix (parseGrafanaIni and similar do lowercase
				// lookups).
				section = strings.ToLower(trimSpace(line[1:end]))
			}
			continue
		}
		// Key=value or key value.
		var key, val string
		if eq := indexByte(line, '='); eq > 0 {
			key = trimSpace(line[:eq])
			val = trimSpace(line[eq+1:])
		} else {
			// Space-delimited (redis.conf / mosquitto style).
			sp := -1
			for i := 0; i < len(line); i++ {
				if line[i] == ' ' || line[i] == '\t' {
					sp = i
					break
				}
			}
			if sp <= 0 {
				continue
			}
			key = trimSpace(line[:sp])
			val = trimSpace(line[sp+1:])
		}
		// Strip inline comments — single left-to-right scan.
		// Take the FIRST position where '#' or ';' is preceded by whitespace.
		// A single pass avoids the double-truncation that occurs when two sequential
		// passes modify `val` independently (e.g. "a ; b # c" → first pass strips
		// at '#' yielding "a ; b", second pass then strips at ';' yielding "a" —
		// coincidentally correct, but fragile).  By finding the earliest
		// whitespace-preceded delimiter we remain correct without depending on
		// iteration order.
		// Values starting with ';' or '#' (e.g. requirepass ;p@ssw0rd!) are
		// preserved because ci>0 is required.
		if val != "" && val[0] != '"' {
			firstCI := -1
			for i := 1; i < len(val); i++ {
				if (val[i] == '#' || val[i] == ';') && (val[i-1] == ' ' || val[i-1] == '\t') {
					firstCI = i
					break
				}
			}
			if firstCI > 0 {
				val = trimSpace(val[:firstCI])
			}
		}
		// Strip surrounding quotes.
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		if key == "" {
			continue
		}
		fullKey := key
		if section != "" {
			fullKey = section + "." + key
		}
		out[fullKey] = val
	}
	return out
}
