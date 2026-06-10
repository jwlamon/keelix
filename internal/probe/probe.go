// Package probe performs outside-in network probing and returns a *model.ProbeResult.
// This is the only package in Keelix that performs real network I/O.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jakelamon/keelix/internal/intel"
	"github.com/jakelamon/keelix/internal/model"
)

const (
	defaultTimeout     = 3 * time.Second
	defaultConcurrency = 50
	bannerReadTimeout  = 800 * time.Millisecond
	bannerMaxBytes     = 256
)

// tlsPorts are ports that speak TLS natively — skip plaintext banner read.
var tlsPorts = map[int]bool{
	443:  true,
	8443: true,
}

// Options controls how Probe operates.
type Options struct {
	Host        string        // target host (FQDN or IP)
	Domains     []string      // extra domains to resolve
	Ports       []int         // candidate ports to test
	Timeout     time.Duration // per-connection timeout; default 3s if zero
	Concurrency int           // max parallel dials; default 50 if zero
}

// Probe performs outside-in probing and returns a non-nil *model.ProbeResult.
// On errors it appends to result.Errors and continues.
func Probe(ctx context.Context, opts Options) *model.ProbeResult {
	result := &model.ProbeResult{
		Host:         opts.Host,
		VantagePoint: "local-egress",
		ProbedAt:     time.Now().UTC(),
		DomainIPs:    make(map[string][]string),
		Reachable:    make(map[int]model.PortProbe),
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	concurrency := opts.Concurrency
	if concurrency == 0 {
		concurrency = defaultConcurrency
	}

	// DNS: resolve the host.
	result.ResolvedIPs = resolveHost(ctx, opts.Host, result)

	// DNS: resolve extra domains.
	for _, domain := range opts.Domains {
		ips := resolveDomain(ctx, domain, result)
		if len(ips) > 0 {
			result.DomainIPs[domain] = ips
		}
	}

	// DNS records: A/AAAA for host and domains.
	addDNSRecords(ctx, opts.Host, result)
	for _, domain := range opts.Domains {
		addDNSRecords(ctx, domain, result)
	}

	// CNAME + wildcard checks for host and domains.
	allDomains := append([]string{opts.Host}, opts.Domains...)
	for _, domain := range allDomains {
		checkCNAME(ctx, domain, result)
		checkWildcard(ctx, domain, result)
	}

	// Port probing — deduplicate first.
	ports := dedup(opts.Ports)

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		select {
		case <-ctx.Done():
			result.Errors = append(result.Errors, "context cancelled during port scan")
			return result
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			pp := probePort(ctx, opts.Host, p, timeout)

			mu.Lock()
			result.Reachable[p] = pp
			if pp.TLS != nil {
				result.Certificates = append(result.Certificates, *pp.TLS)
			}
			mu.Unlock()
		}(port)
	}
	wg.Wait()

	// Sort certificates for determinism.
	sort.Slice(result.Certificates, func(i, j int) bool {
		return result.Certificates[i].Endpoint < result.Certificates[j].Endpoint
	})

	return result
}

// probePort attempts a TCP connection to host:port and gathers banner/TLS info.
func probePort(ctx context.Context, host string, port int, timeout time.Duration) model.PortProbe {
	pp := model.PortProbe{Port: port}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Port is closed/filtered.
		return pp
	}
	pp.Open = true
	_ = conn.Close()

	// Set service name from intel.
	if info, ok := intel.LookupPort(port); ok {
		pp.Service = info.Service
	}

	// For TLS-native ports, skip banner and go straight to TLS.
	if tlsPorts[port] {
		pp.TLS = probeTLS(host, port, timeout)
		return pp
	}

	// Attempt plaintext banner read.
	banner, err := readBanner(ctx, addr, timeout)
	if err == nil && banner != "" {
		pp.Banner = banner
		return pp
	}

	// Banner read failed — try TLS.
	certInfo := probeTLS(host, port, timeout)
	if certInfo != nil {
		pp.TLS = certInfo
	}

	return pp
}

// readBanner opens a TCP connection and reads up to bannerMaxBytes.
func readBanner(ctx context.Context, addr string, timeout time.Duration) (string, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(bannerReadTimeout)); err != nil {
		return "", err
	}

	buf := make([]byte, bannerMaxBytes)
	n, err := conn.Read(buf)
	if n == 0 {
		return "", err
	}

	return trimPrintable(string(buf[:n])), nil
}

// probeTLS dials TLS to host:port and builds a CertInfo from the peer chain.
func probeTLS(host string, port int, timeout time.Duration) *model.CertInfo {
	dialer := &net.Dialer{Timeout: timeout}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- intentional: the prober must connect to self-signed/expired/weak-TLS hosts to detect and REPORT them; results are inspected, never trusted
		ServerName:         host,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), tlsCfg)
	if err != nil {
		return nil
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	chain := cs.PeerCertificates
	if len(chain) == 0 {
		return nil
	}
	leaf := chain[0]

	now := time.Now().UTC()
	daysUntil := int(leaf.NotAfter.Sub(now).Truncate(24*time.Hour).Hours() / 24)

	subject := leaf.Subject.String()
	if subject == "" {
		subject = leaf.Subject.CommonName
	}
	issuer := leaf.Issuer.String()

	selfSigned := isSelfSigned(chain, leaf)

	ci := &model.CertInfo{
		Endpoint:        fmt.Sprintf("%s:%d", host, port),
		Subject:         subject,
		Issuer:          issuer,
		DNSNames:        leaf.DNSNames,
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		SelfSigned:      selfSigned,
		Expired:         now.After(leaf.NotAfter),
		DaysUntilExpiry: daysUntil,
		TLSVersion:      tlsVersionName(cs.Version),
		CipherName:      tls.CipherSuiteName(cs.CipherSuite),
		WeakCipher:      isWeakCipher(cs.Version, cs.CipherSuite),
	}

	return ci
}

// isSelfSigned returns true if the cert chain is self-signed:
// single cert whose Subject == Issuer, OR verify against system roots fails
// with UnknownAuthority for a single-cert chain.
func isSelfSigned(chain []*x509.Certificate, leaf *x509.Certificate) bool {
	if len(chain) == 1 {
		if leaf.Subject.String() == leaf.Issuer.String() {
			return true
		}
		// Try verifying against system roots.
		roots, err := x509.SystemCertPool()
		if err != nil {
			// Can't load system roots — treat as self-signed if subject==issuer.
			return false
		}
		opts := x509.VerifyOptions{Roots: roots}
		_, err = leaf.Verify(opts)
		if err != nil {
			var unknownAuth x509.UnknownAuthorityError
			if isUnknownAuthority(err, &unknownAuth) {
				return true
			}
		}
	}
	return false
}

// isUnknownAuthority checks if the error is x509.UnknownAuthorityError.
func isUnknownAuthority(err error, target *x509.UnknownAuthorityError) bool {
	if err == nil {
		return false
	}
	switch e := err.(type) {
	case x509.UnknownAuthorityError:
		*target = e
		return true
	}
	return false
}

// tlsVersionName maps a TLS version constant to a human-readable string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// isWeakCipher returns true if the negotiated version is below TLS 1.2.
// For TLS 1.3 the cipher suite is always AEAD so we only flag pre-1.2.
func isWeakCipher(version uint16, _ uint16) bool {
	return version < tls.VersionTLS12
}

// resolveHost resolves an FQDN or returns the IP as-is.
func resolveHost(ctx context.Context, host string, result *model.ProbeResult) []string {
	// If host is already an IP, return it directly.
	if net.ParseIP(host) != nil {
		return []string{host}
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("resolve %s: %v", host, err))
		return nil
	}
	return addrs
}

// resolveDomain resolves a domain and appends errors to result on failure.
func resolveDomain(ctx context.Context, domain string, result *model.ProbeResult) []string {
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("resolve domain %s: %v", domain, err))
		return nil
	}
	return addrs
}

// addDNSRecords resolves A/AAAA records for name and appends them to result.DNSRecords.
func addDNSRecords(ctx context.Context, name string, result *model.ProbeResult) {
	// If name is already an IP, emit a single record.
	if ip := net.ParseIP(name); ip != nil {
		recType := "A"
		if ip.To4() == nil {
			recType = "AAAA"
		}
		result.DNSRecords = append(result.DNSRecords, model.DNSRecord{
			Name:  name,
			Type:  recType,
			Value: name,
		})
		return
	}

	// A records (IPv4).
	ipv4s, _ := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	for _, ip := range ipv4s {
		result.DNSRecords = append(result.DNSRecords, model.DNSRecord{
			Name:  name,
			Type:  "A",
			Value: ip.String(),
		})
	}

	// AAAA records (IPv6).
	ipv6s, _ := net.DefaultResolver.LookupIP(ctx, "ip6", name)
	for _, ip := range ipv6s {
		result.DNSRecords = append(result.DNSRecords, model.DNSRecord{
			Name:  name,
			Type:  "AAAA",
			Value: ip.String(),
		})
	}
}

// checkCNAME looks up CNAME for name; if the target doesn't resolve, marks Dangling.
func checkCNAME(ctx context.Context, name string, result *model.ProbeResult) {
	// Skip bare IPs.
	if net.ParseIP(name) != nil {
		return
	}

	cname, err := net.DefaultResolver.LookupCNAME(ctx, name)
	if err != nil {
		return
	}

	// LookupCNAME always returns a FQDN with trailing dot;
	// if it equals name (with or without trailing dot), it's not a CNAME.
	normalName := strings.TrimSuffix(name, ".") + "."
	if cname == normalName {
		return
	}

	// Check if the CNAME target resolves.
	target := strings.TrimSuffix(cname, ".")
	_, err = net.DefaultResolver.LookupHost(ctx, target)
	if err != nil {
		result.DNSRecords = append(result.DNSRecords, model.DNSRecord{
			Name:     name,
			Type:     "CNAME",
			Value:    cname,
			Dangling: true,
		})
	}
}

// checkWildcard probes a random subdomain to detect wildcard DNS.
func checkWildcard(ctx context.Context, domain string, result *model.ProbeResult) {
	// Skip bare IPs.
	if net.ParseIP(domain) != nil {
		return
	}

	// Get the normal resolution set for the domain.
	normalIPs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil || len(normalIPs) == 0 {
		return
	}
	normalSet := ipSet(normalIPs)

	// Probe a random subdomain.
	probe := fmt.Sprintf("dc-probe-%d.%s", rand.Int63(), domain) // #nosec G404 -- non-cryptographic jitter/ordering for probing; not security-sensitive
	probeIPs, err := net.DefaultResolver.LookupHost(ctx, probe)
	if err != nil || len(probeIPs) == 0 {
		return
	}

	// If the random subdomain resolved to the same IP set, it's a wildcard.
	if ipSetsEqual(normalSet, ipSet(probeIPs)) {
		result.DNSRecords = append(result.DNSRecords, model.DNSRecord{
			Name:     domain,
			Type:     "A",
			Value:    probeIPs[0],
			Wildcard: true,
		})
	}
}

// dedup returns a sorted deduplicated slice of ints.
func dedup(ports []int) []int {
	seen := make(map[int]bool, len(ports))
	for _, p := range ports {
		seen[p] = true
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// trimPrintable removes non-printable characters and trims whitespace.
func trimPrintable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// ipSet converts a slice of IPs to a canonical set map.
func ipSet(ips []string) map[string]bool {
	m := make(map[string]bool, len(ips))
	for _, ip := range ips {
		m[ip] = true
	}
	return m
}

// ipSetsEqual returns true if two IP sets are identical.
func ipSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for ip := range a {
		if !b[ip] {
			return false
		}
	}
	return true
}
