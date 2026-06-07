//go:build linux || darwin

package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestParseAppliedMarkerLine_Table exercises parseAppliedMarkerLine directly —
// the streaming-Start marker parser used by startIn. Before this test the
// function was referenced by NO test (only the non-streaming parseAppliedMarker
// was covered in child_linux_test.go), leaving the linux Start applied-marker
// path unguarded. The documented contract: a line equal to the marker prefix
// plus "true"/"false" returns that bool; any non-marker line returns nil so the
// caller falls back to its build-time applied value.
func TestParseAppliedMarkerLine_Table(t *testing.T) {
	cases := []struct {
		name string
		line string
		want *bool // nil => expect nil (non-marker / default)
	}{
		{"applied true", markerLinePrefix + "true", boolp(true)},
		{"applied false", markerLinePrefix + "false", boolp(false)},
		{"non-marker line", "some other stderr noise", nil},
		{"empty line", "", nil},
		{"prefix only, no value", markerLinePrefix, nil},
		{"prefix with junk value", markerLinePrefix + "yes", nil},
		{"marker with leading text (not exact)", "x" + markerLinePrefix + "true", nil},
		{"net-confined marker is not the applied marker", "keelix-sandbox: net-confined=true", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAppliedMarkerLine(tc.line)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("parseAppliedMarkerLine(%q) = %v, want nil", tc.line, *got)
			case tc.want == nil && got == nil:
				// ok
			case tc.want != nil && got == nil:
				t.Fatalf("parseAppliedMarkerLine(%q) = nil, want %v", tc.line, *tc.want)
			case *tc.want != *got:
				t.Fatalf("parseAppliedMarkerLine(%q) = %v, want %v", tc.line, *got, *tc.want)
			}
		})
	}
}

// TestParseAppliedMarkerLine_EmbeddedInMultiLineStderr verifies that the marker
// can be recovered from a realistic multi-line stderr blob by parsing it the
// same way startIn does: take the FIRST line (the trampoline prints the marker
// as its first stderr line) and feed it to parseAppliedMarkerLine. A trailing
// noise line must not change the result, and a leading noise line (marker not
// first) must read as nil — matching the production contract that the marker is
// the first stderr line only.
func TestParseAppliedMarkerLine_EmbeddedInMultiLineStderr(t *testing.T) {
	// Marker first, then noise: startIn reads the first line => true.
	multi := markerLinePrefix + "true\nnpm warn deprecated foo@1.0.0\nlistening on stdio\n"
	first := firstLine(multi)
	got := parseAppliedMarkerLine(first)
	if got == nil || *got != true {
		t.Fatalf("first line of %q parsed to %v, want true", multi, got)
	}

	// Noise first, marker second: the production parser only looks at the first
	// stderr line, so this must read as nil (fall back to build-time applied).
	noisyFirst := "node: warning before marker\n" + markerLinePrefix + "false\n"
	if got := parseAppliedMarkerLine(firstLine(noisyFirst)); got != nil {
		t.Fatalf("non-marker first line of %q parsed to %v, want nil", noisyFirst, *got)
	}
}

// TestStartIn_AppliedReflectsChildMarker is the host-runnable streaming-path
// test: it drives baseRunner.startIn with a trivial /bin/sh child that emits an
// applied=<bool> marker as its first stderr line, then asserts that the
// resulting Session.Applied() reflects that marker (overriding the Tier-0
// build-time default of false). This exercises the real appliedCh goroutine in
// base.go end-to-end on the host. It needs only a POSIX shell, not a sandbox
// kernel feature, so it runs on linux and darwin without Landlock/Seatbelt.
func TestStartIn_AppliedReflectsChildMarker(t *testing.T) {
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh available; streaming marker test is shell-bound")
	}

	cases := []struct {
		name   string
		marker string
		want   bool
	}{
		{"marker true overrides tier0 default", markerLinePrefix + "true", true},
		{"marker false stays false", markerLinePrefix + "false", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &baseRunner{}
			workdir, err := r.workDir()
			if err != nil {
				t.Fatalf("workDir: %v", err)
			}
			defer r.cleanup(workdir)

			// Child: print the marker to stderr (first line), then sit reading stdin
			// so the session stays alive for Applied() to observe. `read x` blocks
			// until Close() shuts the pipe.
			spec := Spec{
				Command: "/bin/sh",
				Args:    []string{"-c", "printf '%s\\n' '" + tc.marker + "' 1>&2; read x"},
				Timeout: 5 * time.Second,
			}
			sess, _, err := r.startIn(context.Background(), spec, workdir)
			if err != nil {
				t.Fatalf("startIn: %v", err)
			}
			defer sess.Close()

			// The Tier-0 build-time default is applied=false; the marker goroutine
			// must override it for the "true" case. Applied() blocks on appliedCh
			// until the goroutine has read the first stderr line.
			if got := sess.Applied(); got != tc.want {
				t.Fatalf("Session.Applied() = %v, want %v (child marker=%q)", got, tc.want, tc.marker)
			}
			// Tier label is unaffected by the marker — it stays tier0 here.
			if tier := sess.Tier(); tier != "tier0" {
				t.Errorf("Session.Tier() = %q, want tier0 for baseRunner", tier)
			}
		})
	}
}

// boolp returns a pointer to b for table-test expectations.
func boolp(b bool) *bool { return &b }

// firstLine returns the first newline-delimited line of s (without the newline),
// mirroring how startIn reads only the first stderr line for the marker.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
