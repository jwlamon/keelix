package collect

// parseNonEmptyLines returns non-blank, non-comment lines from b.
// Comments start with '#'. Useful for pg_hba.conf and /etc/exports projections.
func parseNonEmptyLines(b []byte) []string {
	var out []string
	for _, raw := range splitLines(string(b)) {
		line := trimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		out = append(out, line)
	}
	return out
}
