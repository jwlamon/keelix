package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseUFW(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "ufw_status.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := parseUFW(b)
	if got.Backend != "ufw" {
		t.Errorf("Backend = %q, want ufw", got.Backend)
	}
	if got.DefaultInbound != "deny" {
		t.Errorf("DefaultInbound = %q, want deny", got.DefaultInbound)
	}
	if len(got.Rules) != 2 {
		t.Errorf("Rules = %v, want 2 rule lines", got.Rules)
	}
}

func TestParseNft(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "nft_ruleset.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := parseNft(b)
	if got.Backend != "nftables" {
		t.Errorf("Backend = %q, want nftables", got.Backend)
	}
	if got.DefaultInbound != "drop" {
		t.Errorf("DefaultInbound = %q, want drop (input chain policy)", got.DefaultInbound)
	}
}

func TestParsePf(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "pfctl.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := parsePf(b)
	if got.Backend != "pf" {
		t.Errorf("Backend = %q, want pf", got.Backend)
	}
	if got.DefaultInbound != "block" {
		t.Errorf("DefaultInbound = %q, want block (block drop in all)", got.DefaultInbound)
	}
}

func TestParseUFWInactive(t *testing.T) {
	got := parseUFW([]byte("Status: inactive\n"))
	if got.Backend != "ufw" || got.DefaultInbound != "allow" {
		t.Errorf("inactive ufw = %+v, want backend ufw / default allow", got)
	}
}
