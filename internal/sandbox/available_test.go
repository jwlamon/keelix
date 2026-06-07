package sandbox

import (
	"testing"
)

// TestAvailableIsDeterministic asserts that consecutive calls to Available()
// return the same value (i.e. it is a pure capability query with no side-effects
// that would flip the result between calls in the same process). This test runs
// on all platforms.
func TestAvailableIsDeterministic(t *testing.T) {
	first := Available()
	for i := 0; i < 10; i++ {
		if got := Available(); got != first {
			t.Fatalf("Available() flipped between calls: first=%v call %d=%v", first, i+1, got)
		}
	}
}
