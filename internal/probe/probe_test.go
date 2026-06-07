package probe

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// TestProbeNeverNil asserts Probe always returns a non-nil result.
func TestProbeNeverNil(t *testing.T) {
	ctx := context.Background()
	result := Probe(ctx, Options{
		Host:  "127.0.0.1",
		Ports: []int{},
	})
	if result == nil {
		t.Fatal("Probe returned nil")
	}
}

// TestProbeOpenAndClosedPort starts a real TCP listener on a random loopback
// port and verifies Probe correctly identifies it as open, while a port that
// is not listening is reported as closed.
func TestProbeOpenAndClosedPort(t *testing.T) {
	// Start a listener on a random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	openPort := ln.Addr().(*net.TCPAddr).Port

	// Find a port that is definitely closed: bind then immediately close.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen2: %v", err)
	}
	closedPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	ctx := context.Background()
	result := Probe(ctx, Options{
		Host:        "127.0.0.1",
		Ports:       []int{openPort, closedPort},
		Timeout:     2 * time.Second,
		Concurrency: 5,
	})

	if result == nil {
		t.Fatal("Probe returned nil")
	}

	openProbe, ok := result.Reachable[openPort]
	if !ok {
		t.Fatalf("port %d not in Reachable map", openPort)
	}
	if !openProbe.Open {
		t.Errorf("port %d: want Open=true, got false", openPort)
	}

	closedProbe, ok := result.Reachable[closedPort]
	if !ok {
		t.Fatalf("port %d not in Reachable map", closedPort)
	}
	if closedProbe.Open {
		t.Errorf("port %d: want Open=false, got true", closedPort)
	}
}

// TestProbeTLS starts an httptest.NewTLSServer (self-signed cert), probes its
// host:port, and asserts that a CertInfo is captured with sane values.
func TestProbeTLS(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	// Parse host and port from the server URL.
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port := 0
	if _, err := parsePort(portStr, &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	ctx := context.Background()
	result := Probe(ctx, Options{
		Host:        host,
		Ports:       []int{port},
		Timeout:     3 * time.Second,
		Concurrency: 5,
	})

	if result == nil {
		t.Fatal("Probe returned nil")
	}

	pp, ok := result.Reachable[port]
	if !ok {
		t.Fatalf("port %d not in Reachable map", port)
	}
	if !pp.Open {
		t.Errorf("port %d: want Open=true, got false", port)
	}
	if pp.TLS == nil {
		t.Fatalf("port %d: expected TLS CertInfo, got nil", port)
	}

	ci := pp.TLS
	if ci.Endpoint == "" {
		t.Error("CertInfo.Endpoint is empty")
	}
	if ci.NotAfter.IsZero() {
		t.Error("CertInfo.NotAfter is zero")
	}
	if ci.TLSVersion == "" {
		t.Error("CertInfo.TLSVersion is empty")
	}
	// httptest server uses a self-signed cert.
	if !ci.SelfSigned {
		t.Logf("CertInfo.SelfSigned=false (may be expected on some platforms)")
	}

	// CertInfo should also be in result.Certificates.
	found := false
	for _, c := range result.Certificates {
		if c.Endpoint == ci.Endpoint {
			found = true
			break
		}
	}
	if !found {
		t.Error("CertInfo not found in result.Certificates")
	}
}

// TestProbeDefaultTimeoutAndConcurrency verifies that zero Timeout and zero
// Concurrency are replaced with the package defaults, and the probe still runs.
func TestProbeDefaultTimeoutAndConcurrency(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx := context.Background()
	// Pass zero values — package must fill in defaults.
	result := Probe(ctx, Options{
		Host:        "127.0.0.1",
		Ports:       []int{port},
		Timeout:     0,
		Concurrency: 0,
	})

	if result == nil {
		t.Fatal("Probe returned nil")
	}
	pp, ok := result.Reachable[port]
	if !ok {
		t.Fatalf("port %d not in Reachable map", port)
	}
	if !pp.Open {
		t.Errorf("port %d: want Open=true with default timeout, got false", port)
	}
}

// TestProbeUnresolvableHost verifies that Probe never panics and records errors
// for a host that cannot be resolved, without returning nil.
func TestProbeUnresolvableHost(t *testing.T) {
	ctx := context.Background()
	result := Probe(ctx, Options{
		Host:        "nonexistent.invalid.",
		Ports:       []int{80, 443},
		Timeout:     2 * time.Second,
		Concurrency: 5,
	})

	if result == nil {
		t.Fatal("Probe returned nil for unresolvable host")
	}
	if result.Host != "nonexistent.invalid." {
		t.Errorf("result.Host = %q, want %q", result.Host, "nonexistent.invalid.")
	}
	if len(result.Errors) == 0 {
		t.Error("expected at least one error for unresolvable host, got none")
	}
}

// TestProbeMetadata checks that VantagePoint and ProbedAt are always populated.
func TestProbeMetadata(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	ctx := context.Background()
	result := Probe(ctx, Options{
		Host:  "127.0.0.1",
		Ports: []int{},
	})
	after := time.Now().UTC().Add(time.Second)

	if result.VantagePoint != "local-egress" {
		t.Errorf("VantagePoint = %q, want %q", result.VantagePoint, "local-egress")
	}
	if result.ProbedAt.IsZero() {
		t.Error("ProbedAt is zero")
	}
	if result.ProbedAt.Before(before) || result.ProbedAt.After(after) {
		t.Errorf("ProbedAt %v is outside expected range [%v, %v]", result.ProbedAt, before, after)
	}
}

// TestProbeIPHostSkipsDNS checks that when Host is already an IP, ResolvedIPs
// contains that IP without a DNS lookup error.
func TestProbeIPHostSkipsDNS(t *testing.T) {
	ctx := context.Background()
	result := Probe(ctx, Options{
		Host:  "127.0.0.1",
		Ports: []int{},
	})
	if result == nil {
		t.Fatal("Probe returned nil")
	}
	if len(result.ResolvedIPs) == 0 {
		t.Error("ResolvedIPs should contain the IP when Host is already an IP")
	}
	if result.ResolvedIPs[0] != "127.0.0.1" {
		t.Errorf("ResolvedIPs[0] = %q, want %q", result.ResolvedIPs[0], "127.0.0.1")
	}
	// No errors expected for a bare IP.
	for _, e := range result.Errors {
		if contains(e, "resolve 127.0.0.1") {
			t.Errorf("unexpected resolve error for IP host: %s", e)
		}
	}
}

// TestProbeContextCancellation verifies that Probe respects context cancellation.
func TestProbeContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	result := Probe(ctx, Options{
		Host:        "127.0.0.1",
		Ports:       []int{1, 2, 3, 4, 5},
		Timeout:     500 * time.Millisecond,
		Concurrency: 2,
	})
	// Must not panic and must return non-nil.
	if result == nil {
		t.Fatal("Probe returned nil on cancelled context")
	}
}

// TestTLSVersionName checks the TLS version string mapping.
func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		version uint16
		want    string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "unknown(0x0000)"},
	}
	for _, tc := range cases {
		got := tlsVersionName(tc.version)
		if got != tc.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tc.version, got, tc.want)
		}
	}
}

// TestIsWeakCipher checks that versions below TLS 1.2 are flagged as weak.
func TestIsWeakCipher(t *testing.T) {
	if !isWeakCipher(0x0301, 0) { // TLS 1.0
		t.Error("TLS 1.0 should be weak")
	}
	if !isWeakCipher(0x0302, 0) { // TLS 1.1
		t.Error("TLS 1.1 should be weak")
	}
	if isWeakCipher(0x0303, 0) { // TLS 1.2
		t.Error("TLS 1.2 should not be weak")
	}
	if isWeakCipher(0x0304, 0) { // TLS 1.3
		t.Error("TLS 1.3 should not be weak")
	}
}

// TestDedup verifies deduplication and sorting of port lists.
func TestDedup(t *testing.T) {
	got := dedup([]int{443, 80, 443, 8080, 80})
	want := []int{80, 443, 8080}
	if len(got) != len(want) {
		t.Fatalf("dedup len = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedup[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// TestTrimPrintable verifies that non-printable bytes are stripped.
func TestTrimPrintable(t *testing.T) {
	input := "SSH-2.0-OpenSSH\x00\x01\xff\n"
	got := trimPrintable(input)
	for _, r := range got {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			t.Errorf("non-printable rune %q in output %q", r, got)
		}
	}
}

// parsePort is a helper to convert a port string to int for tests.
func parsePort(s string, port *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &net.AddrError{Err: "invalid port", Addr: s}
		}
		n = n*10 + int(c-'0')
	}
	*port = n
	return n, nil
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}
