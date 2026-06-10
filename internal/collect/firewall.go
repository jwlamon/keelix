package collect

import (
	"strings"

	"github.com/jakelamon/keelix/internal/model"
)

// parseUFW parses `ufw status verbose`. DefaultInbound is read from the
// "Default: <x> (incoming)" line; an inactive firewall reports "allow".
// Rules are the "To Action From" table rows (header and separator dropped).
func parseUFW(b []byte) model.FirewallState {
	fw := model.FirewallState{Backend: "ufw", DefaultInbound: "allow"}
	var inTable bool
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Status:") && strings.Contains(line, "inactive"):
			fw.DefaultInbound = "allow"
		case strings.HasPrefix(line, "Default:"):
			fw.DefaultInbound = ufwIncomingDefault(line)
		case strings.HasPrefix(line, "To") && strings.Contains(line, "Action"):
			inTable = true
		case strings.HasPrefix(line, "--"):
			// separator row — stay in table
		case inTable && line != "":
			fw.Rules = append(fw.Rules, line)
		}
	}
	return fw
}

// ufwIncomingDefault extracts the policy word preceding "(incoming)".
func ufwIncomingDefault(line string) string {
	idx := strings.Index(line, "(incoming)")
	if idx < 0 {
		return "allow"
	}
	fields := strings.Fields(line[:idx])
	if len(fields) == 0 {
		return "allow"
	}
	return strings.TrimSpace(fields[len(fields)-1])
}

// parseNft parses `nft list ruleset`. DefaultInbound is the policy of the input
// hook chain; rule lines are non-brace, non-chain statements.
func parseNft(b []byte) model.FirewallState {
	fw := model.FirewallState{Backend: "nftables", DefaultInbound: "accept"}
	var inInput bool
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if strings.Contains(line, "hook input") {
			inInput = true
			if i := strings.Index(line, "policy "); i >= 0 {
				rest := strings.TrimSuffix(strings.TrimSpace(line[i+len("policy "):]), ";")
				if rest != "" {
					fw.DefaultInbound = strings.Fields(rest)[0]
				}
			}
			continue
		}
		if line == "}" {
			inInput = false
			continue
		}
		if inInput && line != "" && !strings.HasPrefix(line, "type ") {
			fw.Rules = append(fw.Rules, line)
		}
	}
	return fw
}

// parsePf parses pfctl output. DefaultInbound is "block" when a "block ... in all"
// rule is present, otherwise "allow". All rule lines are captured verbatim.
func parsePf(b []byte) model.FirewallState {
	fw := model.FirewallState{Backend: "pf", DefaultInbound: "allow"}
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "Status:") || strings.HasPrefix(line, "Debug:") {
			continue
		}
		if strings.HasPrefix(line, "block") && strings.Contains(line, " in ") && strings.Contains(line, "all") {
			fw.DefaultInbound = "block"
		}
		if strings.HasPrefix(line, "block") || strings.HasPrefix(line, "pass") {
			fw.Rules = append(fw.Rules, line)
		}
	}
	return fw
}
