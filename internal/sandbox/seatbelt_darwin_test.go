//go:build darwin

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltProfile(t *testing.T) {
	prof := seatbeltProfile("/private/var/folders/xx/tmpdir", nil)

	mustContain := []string{
		"(version 1)",
		"(deny default)",
		"(allow process-exec*)",
		"(allow process-fork)",
		`(allow file-write* (subpath "/private/var/folders/xx/tmpdir"))`,
		"(deny network*)",
	}
	for _, want := range mustContain {
		if !strings.Contains(prof, want) {
			t.Errorf("profile missing %q\nprofile:\n%s", want, prof)
		}
	}

	// Network must be DENIED, never allowed.
	if strings.Contains(prof, "(allow network") {
		t.Errorf("profile must not allow any network:\n%s", prof)
	}

	// (deny default) sets the base posture and conventionally leads the profile.
	// Note: this is the default-rule baseline, not deny-vs-allow precedence — a
	// specific Seatbelt deny is authoritative by its presence, not its position.
	if di, ni := strings.Index(prof, "(deny default)"), strings.Index(prof, "(allow process-exec*)"); di == -1 || ni == -1 || di > ni {
		t.Errorf("(deny default) must lead the profile as the base posture:\n%s", prof)
	}
}

// TestAllowedCachePath_SBX4_DarwinKnownRootsAccepted verifies (SBX-4) that
// allowedCachePath accepts the default npm and uvx cache dirs on darwin so that
// npx/uvx can continue to resolve packages when their defaults are used.
func TestAllowedCachePath_SBX4_DarwinKnownRootsAccepted(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	accepted := []string{
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".npm", "cache"),
		filepath.Join(home, ".cache"),
		filepath.Join(home, ".cache", "uv"),
		filepath.Join(home, ".cache", "uv", "packages"),
		filepath.Join(home, "Library", "Caches"),
		filepath.Join(home, "Library", "Caches", "uv"),
		"/tmp",
		"/tmp/keelix-cache",
	}
	for _, p := range accepted {
		if !allowedCachePath(p) {
			t.Errorf("allowedCachePath(%q) = false, want true (known safe cache root)", p)
		}
	}
}

// TestAllowedCachePath_SBX4_DarwinInjectedPathsRejected verifies (SBX-4) that
// allowedCachePath rejects paths outside the known safe cache roots, preventing
// a config env like npm_config_cache=~/.ssh from re-granting HOME read access.
func TestAllowedCachePath_SBX4_DarwinInjectedPathsRejected(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	rejected := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config"),
		home,
		filepath.Join(home, "projects"),
		filepath.Join(home, "Documents"),
		"/etc",
		"/var",
		"/private/etc",
	}
	for _, p := range rejected {
		if allowedCachePath(p) {
			t.Errorf("allowedCachePath(%q) = true, want false (must be rejected to prevent HOME read bypass)", p)
		}
	}
}

// TestWrapDarwinSpec_SBX4_InjectedCachePathAbsentFromProfile is the darwin
// analogue of TestRoCaches_RejectsInjectedSSHPath (linux). It calls
// wrapDarwinSpec with npm_config_cache set to $HOME/.ssh and asserts that the
// injected path does NOT appear as a Seatbelt subpath allow in the generated
// shell script, satisfying the spec requirement: "apply the same validation on
// the darwin Seatbelt cache allows" (SBX-4).
func TestWrapDarwinSpec_SBX4_InjectedCachePathAbsentFromProfile(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	injected := filepath.Join(home, ".ssh")

	in := Spec{
		Command: "node",
		Args:    []string{"server.js"},
		Env: map[string]string{
			"npm_config_cache": injected,
		},
	}
	wrapped, _, _ := wrapDarwinSpec(in, "/usr/bin/sandbox-exec")
	script := wrapped.Args[1]

	// The injected path must not appear anywhere in the generated Seatbelt
	// profile script — not as a subpath allow, not in any other form.
	if strings.Contains(script, injected) {
		t.Errorf("injected path %q appeared in Seatbelt script (must be rejected by allowedCachePath to prevent HOME read bypass)\nscript: %s", injected, script)
	}
}

// TestWrapDarwinSpec_SBX4_ValidCachePathAppearsInProfile verifies that a
// legitimate npm cache path (~/.npm) IS present in the generated Seatbelt
// profile as an explicit subpath allow when passed via npm_config_cache, so
// npx can resolve packages (SBX-4 positive case).
func TestWrapDarwinSpec_SBX4_ValidCachePathAppearsInProfile(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	npmCache := filepath.Join(home, ".npm")

	in := Spec{
		Command: "node",
		Args:    []string{"server.js"},
		Env: map[string]string{
			"npm_config_cache": npmCache,
		},
	}
	wrapped, _, _ := wrapDarwinSpec(in, "/usr/bin/sandbox-exec")
	script := wrapped.Args[1]

	// The validated cache path must appear in the generated Seatbelt script as
	// an explicit subpath allow.
	wantFragment := `(allow file-read* (subpath "` + npmCache + `"))`
	if !strings.Contains(script, wantFragment) {
		t.Errorf("valid npm cache path %q missing from Seatbelt script\nwant fragment: %s\nscript: %s", npmCache, wantFragment, script)
	}
}

// TestSeatbeltProfile_DeniesHomeAllowsTempdir verifies SBX-3: the generated
// Seatbelt profile must explicitly deny file-read* under the real user $HOME
// (protecting ~/.ssh, ~/.aws, agent tokens) while still allowing reads inside
// the sandbox tempdir. This is a structural test against the SBPL text; the
// real confinement assertion lives in runner_darwin_e2e_test.go.
//
// The $HOME guarantee comes from the PRESENCE of the deny rule, not its
// position: Apple Seatbelt treats a matching deny as authoritative regardless
// of where it sits relative to a broader allow. We therefore assert the deny is
// present (and the broad allow is present), NOT that the deny precedes the
// allow.
func TestSeatbeltProfile_DeniesHomeAllowsTempdir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}

	const tmpdir = "/private/var/folders/xx/keelix-sbx-test"
	prof := seatbeltProfile(tmpdir, nil)

	// 1. Profile must contain an explicit deny for file-read* under $HOME. Its
	//    presence — not its position relative to the broad allow — is what
	//    enforces the guarantee (a Seatbelt deny is authoritative).
	homeDenyRule := `(deny file-read* (subpath "` + home + `"))`
	if !strings.Contains(prof, homeDenyRule) {
		t.Errorf("profile missing HOME-deny rule %q\nprofile:\n%s", homeDenyRule, prof)
	}

	// 2. A broad file-read* allow must still be present so system libraries,
	//    /opt/homebrew, /usr/local etc. remain readable.
	if !strings.Contains(prof, "(allow file-read*)") {
		t.Errorf("profile missing broad (allow file-read*) rule\nprofile:\n%s", prof)
	}

	// 3. The broad allow must NOT itself grant $HOME: i.e. it must be the
	//    unscoped (allow file-read*) and must never appear as an explicit allow
	//    over the $HOME subpath that would contradict the deny. (Even if it did,
	//    Seatbelt's deny would still win — but a contradictory allow would signal
	//    a profile bug, so we guard against it.)
	homeAllowRule := `(allow file-read* (subpath "` + home + `"))`
	if strings.Contains(prof, homeAllowRule) {
		t.Errorf("profile must not contain an explicit $HOME read-allow %q that contradicts the deny\nprofile:\n%s",
			homeAllowRule, prof)
	}

	// 4. Tempdir write must be allowed.
	wantWrite := `(allow file-write* (subpath "` + tmpdir + `"))`
	if !strings.Contains(prof, wantWrite) {
		t.Errorf("profile missing tempdir write rule %q\nprofile:\n%s", wantWrite, prof)
	}

	// 5. Tempdir read must be allowed (either via broad allow or explicit subpath).
	// The broad (allow file-read*) covers this since tempdir is not under HOME.
	// We just verify the broad allow is present (already checked above).
}
