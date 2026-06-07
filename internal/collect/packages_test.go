package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAptUpgradable(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "apt_upgradable.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// rebootRequired and distroEOL are sourced separately by the wrapper; pass them in.
	got := parseAptState(b, true, false)
	if got.Manager != "apt" {
		t.Errorf("Manager = %q, want apt", got.Manager)
	}
	if got.SecurityUpdatesPending != 2 {
		t.Errorf("SecurityUpdatesPending = %d, want 2 (two -security lines)", got.SecurityUpdatesPending)
	}
	if !got.RebootRequired {
		t.Error("RebootRequired = false, want true")
	}
	if got.DistroEOL {
		t.Error("DistroEOL = true, want false")
	}
}

func TestParseSoftwareUpdate(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "softwareupdate.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := parseSoftwareUpdate(b)
	if got.Manager != "softwareupdate" {
		t.Errorf("Manager = %q, want softwareupdate", got.Manager)
	}
	if got.SecurityUpdatesPending != 2 {
		t.Errorf("SecurityUpdatesPending = %d, want 2", got.SecurityUpdatesPending)
	}
	if !got.RebootRequired {
		t.Error("RebootRequired = false, want true (a restart-action label present)")
	}
}

func TestParseAptEmpty(t *testing.T) {
	got := parseAptState([]byte("Listing...\n"), false, false)
	if got.SecurityUpdatesPending != 0 {
		t.Errorf("SecurityUpdatesPending = %d, want 0", got.SecurityUpdatesPending)
	}
}
