package service

// Tests for R4-4: arrPortFromStack must use an ordered slice (longest keyword
// first) instead of a map so the result is deterministic when an image base
// matches multiple *arr keywords.

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// TestArrPortFromStack_OrderedSlice verifies R4-4: arrImageDefaultPorts must be
// an ordered []struct (not a map) so longer/more-specific keywords take
// precedence over shorter ones. We verify this by asserting that the package-
// level variable is of the slice type — and that it resolves specific *arr
// images to their correct ports (proving longest-keyword-first wins).
func TestArrPortFromStack_OrderedSlice(t *testing.T) {
	// Verify structure: arrImageDefaultPorts must be a slice, not a map.
	// The declaration check is a compile-time assertion via typed assignment.
	// If the code still uses a map, this assignment won't compile.
	var _ []struct{ keyword, port string } = arrImageDefaultPorts

	cases := []struct {
		desc     string
		image    string
		wantPort string
	}{
		{"sonarr", "linuxserver/sonarr:latest", "8989"},
		{"prowlarr", "linuxserver/prowlarr:latest", "9696"},
		{"lidarr", "linuxserver/lidarr:latest", "8686"},
		{"readarr", "linuxserver/readarr:latest", "8787"},
		{"radarr", "linuxserver/radarr:latest", "7878"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			stack := &model.Stack{
				Services: []*model.Service{
					{Name: "arr", Image: tc.image},
				},
			}
			got := arrPortFromStack(stack)
			if got != tc.wantPort {
				t.Errorf("arrPortFromStack(%q) = %q, want %q", tc.image, got, tc.wantPort)
			}
		})
	}
}

// TestArrPortFromStack_NoMatch verifies the nil-stack and no-match paths.
func TestArrPortFromStack_NoMatch(t *testing.T) {
	if got := arrPortFromStack(nil); got != "" {
		t.Errorf("nil stack: got %q, want empty string", got)
	}
	stack := &model.Stack{
		Services: []*model.Service{
			{Name: "plex", Image: "plexinc/pms-docker:latest"},
		},
	}
	if got := arrPortFromStack(stack); got != "" {
		t.Errorf("no-match stack: got %q, want empty string", got)
	}
}
