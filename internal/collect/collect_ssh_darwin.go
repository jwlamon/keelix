//go:build darwin

package collect

import "github.com/jakelamon/keelix/internal/model"

// collectSSH is not implemented on macOS; sshd configuration parsing
// is Linux-only for SP2. Returns an empty, non-error result.
func collectSSH(_ Options) (model.ConfigFact, error) {
	return model.ConfigFact{}, nil
}
