//go:build !linux && !darwin

package sandbox

// NewRunner returns the strongest sandbox Runner the host supports. On
// platforms without a dedicated isolation backend it returns the Tier-0
// baseRunner, which still drops the parent env, uses a throwaway cwd, and
// group-kills on timeout. The linux and darwin builds override this with
// Landlock and Seatbelt runners respectively.
func NewRunner() Runner {
	return &baseRunner{}
}
