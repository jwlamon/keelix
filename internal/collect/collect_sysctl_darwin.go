//go:build darwin

package collect

import "github.com/jakelamon/keelix/internal/model"

// collectSysctl is not implemented on macOS; /proc/sys does not exist.
// Returns an empty, non-error result.
func collectSysctl() (model.ConfigFact, error) {
	return model.ConfigFact{}, nil
}
