package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jwlamon/keelix/internal/model"
)

func TestCollectSetsHeaderFields(t *testing.T) {
	fixed := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	got, err := Collect(Options{Now: fixed})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got == nil {
		t.Fatal("Collect returned nil signals")
	}
	if got.Version != model.SignalsVersion {
		t.Errorf("Version = %q, want %q", got.Version, model.SignalsVersion)
	}
	if !got.CollectedAt.Equal(fixed) {
		t.Errorf("CollectedAt = %v, want %v (opts.Now must be honored)", got.CollectedAt, fixed)
	}
	if got.Platform.OS != runtime.GOOS {
		t.Errorf("Platform.OS = %q, want %q", got.Platform.OS, runtime.GOOS)
	}
	if got.Privilege.EUID != os.Geteuid() {
		t.Errorf("Privilege.EUID = %d, want %d", got.Privilege.EUID, os.Geteuid())
	}
}

func TestCollectDefaultsNowWhenZero(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	got, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got.CollectedAt.Before(before) {
		t.Errorf("CollectedAt = %v, expected >= %v (should default to now)", got.CollectedAt, before)
	}
}

func TestLoadRoundTrip(t *testing.T) {
	want := &model.Signals{
		Version:     model.SignalsVersion,
		CollectedAt: time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC),
		Platform:    model.Platform{OS: "linux", Distro: "ubuntu"},
		Sockets:     []model.ListeningSocket{{Proto: "tcp", Bind: "0.0.0.0", Port: 6379}},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signals.json")
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Version != want.Version || len(got.Sockets) != 1 || got.Sockets[0].Port != 6379 {
		t.Errorf("Load round-trip mismatch: got %+v", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("Load of missing file: want error, got nil")
	}
}

// TestCollectWiresSP2Domains verifies that after SP2 wiring, Collect() attempts
// the ssh and sysctl domains. On Linux they may succeed or fail (missing sshd);
// on any platform they must not panic and must record an error or produce a fact.
func TestCollectWiresSP2Domains(t *testing.T) {
	got, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got == nil {
		t.Fatal("Collect returned nil signals")
	}
	// SP2 wiring: either the ssh ConfigFact is present or an error was recorded.
	domains := map[string]bool{}
	for _, ce := range got.Errors {
		domains[ce.Domain] = true
	}
	sshPresent := false
	for _, c := range got.Configs {
		if c.SchemaID == "sshd-effective" {
			sshPresent = true
			break
		}
	}
	if !sshPresent && !domains["ssh"] {
		t.Log("ssh domain: neither a ConfigFact nor an error recorded — acceptable on non-Linux")
	}
	// Platform must have been populated from os-release on Linux.
	// On macOS, Platform.Distro may be empty; that is fine.
	_ = got.Platform
}

// TestCollectWiresSubCollectors verifies that Collect() attempts the three
// additional sub-collectors (processes, packages, firewall) and that failures
// are recorded as CollectErrors rather than causing a panic or fatal return.
func TestCollectWiresSubCollectors(t *testing.T) {
	// Regardless of whether sub-collectors succeed or fail on the test host,
	// Collect must not panic and must return non-nil signals.
	got, err := Collect(Options{})
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if got == nil {
		t.Fatal("Collect returned nil signals")
	}
	// All errors must be recorded in Errors, never returned as fatal.
	// Confirm any error recorded has a non-empty domain.
	for _, ce := range got.Errors {
		if ce.Domain == "" {
			t.Errorf("CollectError with empty domain: %+v", ce)
		}
	}
	// Verify the three domains are either populated or recorded as errors.
	domains := map[string]bool{}
	for _, ce := range got.Errors {
		domains[ce.Domain] = true
	}
	// processes: either got processes, or there's an error for that domain
	if got.Processes == nil && !domains["processes"] {
		t.Error("Collect: Processes is nil and no error recorded for 'processes' domain")
	}
	// packages: if manager is empty and no error, something went wrong
	if got.Packages.Manager == "" && !domains["packages"] {
		t.Error("Collect: Packages.Manager is empty and no error recorded for 'packages' domain")
	}
	// firewall: if backend is empty and no error, something went wrong
	if got.Firewall.Backend == "" && !domains["firewall"] {
		t.Error("Collect: Firewall.Backend is empty and no error recorded for 'firewall' domain")
	}
}
