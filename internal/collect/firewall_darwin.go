//go:build darwin

package collect

import (
	"os/exec"

	"github.com/jwlamon/keelix/internal/model"
)

// collectFirewall runs pfctl (info + rules) and delegates to the pure parser.
func collectFirewall() (model.FirewallState, error) {
	info, _ := exec.Command("pfctl", "-s", "info").Output()
	rules, err := exec.Command("pfctl", "-s", "rules").Output()
	if err != nil {
		return model.FirewallState{Backend: "pf", DefaultInbound: "allow"}, err
	}
	combined := append(append([]byte{}, info...), rules...)
	return parsePf(combined), nil
}
