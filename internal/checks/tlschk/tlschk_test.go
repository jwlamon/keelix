package tlschk_test

import (
	"testing"
	"time"

	_ "github.com/jakelamon/keelix/internal/checks/tlschk"
	"github.com/jakelamon/keelix/internal/model"
)

func runCheck(id string, ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c.Run(ctx)
		}
	}
	panic("check not registered: " + id)
}

// makeProbeWithCerts builds a ProbeResult containing the given certificates.
func makeProbeWithCerts(certs ...model.CertInfo) *model.ProbeResult {
	return &model.ProbeResult{
		Host:         "example.com",
		Certificates: certs,
		Reachable:    map[int]model.PortProbe{},
	}
}

// makeProbeWithPorts builds a ProbeResult with only port reachability set.
func makeProbeWithPorts(open ...int) *model.ProbeResult {
	r := make(map[int]model.PortProbe, len(open))
	for _, p := range open {
		r[p] = model.PortProbe{Port: p, Open: true}
	}
	return &model.ProbeResult{
		Host:      "example.com",
		Reachable: r,
	}
}

// ---- TLS001 ----

func TestTLS001_Warning_Port80OpenNo443(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithPorts(80),
	}
	findings := runCheck("TLS001", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", f.Severity)
	}
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
}

func TestTLS001_Pass_443Open(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithPorts(80, 443),
	}
	findings := runCheck("TLS001", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestTLS001_NilIfPort80NotOpen(t *testing.T) {
	// Neither port open: not applicable.
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithPorts(),
	}
	if runCheck("TLS001", ctx) != nil {
		t.Error("expected nil when port 80 is not open")
	}
}

func TestTLS001_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	if runCheck("TLS001", ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- TLS002 ----

func TestTLS002_Critical_ExpiredCert(t *testing.T) {
	expiredCert := model.CertInfo{
		Endpoint:        "app:443",
		Expired:         true,
		DaysUntilExpiry: -30,
		NotAfter:        time.Now().Add(-30 * 24 * time.Hour),
	}
	selfSignedWeakCert := model.CertInfo{
		Endpoint:   "b:443",
		SelfSigned: true,
		WeakCipher: true,
		TLSVersion: "TLS 1.1",
	}
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(expiredCert, selfSignedWeakCert),
	}

	findings := runCheck("TLS002", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected Critical, got %v", f.Severity)
	}
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
	if f.Resource != "app:443" {
		t.Errorf("expected resource 'app:443', got %q", f.Resource)
	}
}

func TestTLS002_NilIfNoCerts(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(),
	}
	if runCheck("TLS002", ctx) != nil {
		t.Error("expected nil when no certificates present")
	}
}

func TestTLS002_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	if runCheck("TLS002", ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- TLS003 ----

func TestTLS003_Warning_SelfSigned(t *testing.T) {
	selfSignedCert := model.CertInfo{
		Endpoint:   "b:443",
		SelfSigned: true,
		WeakCipher: true,
		TLSVersion: "TLS 1.1",
	}
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(selfSignedCert),
	}

	findings := runCheck("TLS003", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", f.Severity)
	}
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
	if f.Resource != "b:443" {
		t.Errorf("expected resource 'b:443', got %q", f.Resource)
	}
}

func TestTLS003_NilIfNoCerts(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(),
	}
	if runCheck("TLS003", ctx) != nil {
		t.Error("expected nil when no certificates present")
	}
}

// ---- TLS004 ----

func TestTLS004_Warning_WeakCipher(t *testing.T) {
	weakCert := model.CertInfo{
		Endpoint:   "b:443",
		SelfSigned: true,
		WeakCipher: true,
		TLSVersion: "TLS 1.1",
		CipherName: "RC4-MD5",
	}
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(weakCert),
	}

	findings := runCheck("TLS004", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", f.Severity)
	}
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
}

func TestTLS004_Warning_WeakTLSVersion(t *testing.T) {
	// TLS 1.0 alone should flag even without WeakCipher=true.
	cert := model.CertInfo{
		Endpoint:   "c:443",
		WeakCipher: false,
		TLSVersion: "TLS 1.0",
	}
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(cert),
	}
	findings := runCheck("TLS004", ctx)
	if len(findings) != 1 || findings[0].Passed {
		t.Errorf("expected 1 failing finding for TLS 1.0, got %v", findings)
	}
}

func TestTLS004_NilIfNoCerts(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(),
	}
	if runCheck("TLS004", ctx) != nil {
		t.Error("expected nil when no certificates present")
	}
}

func TestTLS004_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	if runCheck("TLS004", ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- Combined scenario from spec ----

// TestTLSCombined_SpecScenario verifies the full scenario from the spec:
// Probe with Certificates [{Endpoint:"app:443",Expired:true},{Endpoint:"b:443",SelfSigned:true,WeakCipher:true}]
// -> TLS002 critical, TLS003 warning, TLS004 warning.
func TestTLSCombined_SpecScenario(t *testing.T) {
	certs := []model.CertInfo{
		{
			Endpoint:        "app:443",
			Expired:         true,
			DaysUntilExpiry: -5,
			NotAfter:        time.Now().Add(-5 * 24 * time.Hour),
		},
		{
			Endpoint:   "b:443",
			SelfSigned: true,
			WeakCipher: true,
			TLSVersion: "TLS 1.1",
		},
	}
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithCerts(certs...),
	}

	tls002Findings := runCheck("TLS002", ctx)
	if len(tls002Findings) != 1 || tls002Findings[0].Severity != model.SeverityCritical {
		t.Errorf("TLS002: expected 1 critical finding, got %v", tls002Findings)
	}

	tls003Findings := runCheck("TLS003", ctx)
	if len(tls003Findings) != 1 || tls003Findings[0].Severity != model.SeverityWarning {
		t.Errorf("TLS003: expected 1 warning finding, got %v", tls003Findings)
	}

	tls004Findings := runCheck("TLS004", ctx)
	if len(tls004Findings) != 1 || tls004Findings[0].Severity != model.SeverityWarning {
		t.Errorf("TLS004: expected 1 warning finding, got %v", tls004Findings)
	}
}
