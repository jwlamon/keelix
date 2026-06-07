//go:build linux

package collect

import (
	"os/exec"

	"github.com/jwlamon/keelix/internal/model"
)

// collectFirewall prefers ufw; falls back to nftables. A clean "no firewall"
// state is reported when neither tool is present.
func collectFirewall() (model.FirewallState, error) {
	if out, err := exec.Command("ufw", "status", "verbose").Output(); err == nil {
		return parseUFW(out), nil
	}
	if out, err := exec.Command("nft", "list", "ruleset").Output(); err == nil {
		return parseNft(out), nil
	}
	return model.FirewallState{Backend: "none", DefaultInbound: "allow"}, nil
}
