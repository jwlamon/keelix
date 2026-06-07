//go:build linux

package sandbox

import "testing"

// TestSelectTier_NeverReturnsBwrap is the SBX-9(c) security guarantee:
// selectTier must NEVER return "bwrap" because bwrap is never exec'd by the
// runner (the trampoline uses the Landlock path). Returning "bwrap" would be a
// false tier report — the operator would believe mount+netns isolation was
// applied when only Landlock (or Tier-0) was actually used.
func TestSelectTier_NeverReturnsBwrap(t *testing.T) {
	cases := []struct {
		name             string
		bwrapPath        string
		usernsRestricted bool
	}{
		{"bwrap on PATH, userns unrestricted", "/usr/bin/bwrap", false},
		{"bwrap on PATH, userns restricted", "/usr/bin/bwrap", true},
		{"no bwrap, userns unrestricted", "", false},
		{"no bwrap, userns restricted", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectTier(tc.bwrapPath, tc.usernsRestricted)
			if got == "bwrap" {
				t.Errorf("selectTier(%q, %v) = %q; must NEVER return 'bwrap' (never exec'd)",
					tc.bwrapPath, tc.usernsRestricted, got)
			}
		})
	}
}
