package proxy_test

import (
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/proxy"
	"github.com/jakelamon/keelix/internal/model"
)

// runCheck finds a registered check by ID and calls Run.
func runCheck(id string, ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c.Run(ctx)
		}
	}
	panic("check not registered: " + id)
}

// makeProxyStack builds a stack with a Traefik proxy having two routes:
//   - "app.x.com" -> service "app": no TLS, no auth, no security headers, not wildcard
//   - "*.x.com"   -> service "wild": TLS, auth, security headers, wildcard
func makeProxyStack() *model.Stack {
	return &model.Stack{
		Proxy: &model.ProxyConfig{
			Kind:             model.ProxyTraefik,
			DashboardExposed: true,
			Routes: []model.ProxyRoute{
				{
					Host:            "app.x.com",
					Service:         "app",
					TLS:             false,
					HasAuth:         false,
					SecurityHeaders: false,
					Wildcard:        false,
				},
				{
					Host:            "*.x.com",
					Service:         "wild",
					TLS:             true,
					HasAuth:         true,
					SecurityHeaders: true,
					Wildcard:        true,
				},
			},
		},
	}
}

// nilProxyStack has no proxy.
func nilProxyStack() *model.Stack {
	return &model.Stack{}
}

// ---- PRX001 ----

func TestPRX001_FlagsNoAuthRoute(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeProxyStack()}
	findings := runCheck("PRX001", ctx)

	// Only the "app.x.com" route lacks auth.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
	if f.Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", f.Severity)
	}
	if f.Service != "app" {
		t.Errorf("expected service 'app', got %q", f.Service)
	}
	if f.Resource != "app.x.com" {
		t.Errorf("expected resource 'app.x.com', got %q", f.Resource)
	}
}

func TestPRX001_NilProxy_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: nilProxyStack()}
	if runCheck("PRX001", ctx) != nil {
		t.Error("expected nil when proxy is nil")
	}
}

func TestPRX001_Pass_AllHaveAuth(t *testing.T) {
	stack := &model.Stack{
		Proxy: &model.ProxyConfig{
			Kind: model.ProxyTraefik,
			Routes: []model.ProxyRoute{
				{Host: "a.x.com", Service: "a", HasAuth: true, TLS: true, SecurityHeaders: true},
			},
		},
	}
	ctx := &model.ScanContext{Stack: stack}
	findings := runCheck("PRX001", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

// ---- PRX002 ----

func TestPRX002_FlagsHTTPRoute(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeProxyStack()}
	findings := runCheck("PRX002", ctx)

	// Only the "app.x.com" route lacks TLS.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
	if f.Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", f.Severity)
	}
	if f.Resource != "app.x.com" {
		t.Errorf("expected resource 'app.x.com', got %q", f.Resource)
	}
}

func TestPRX002_NilProxy_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: nilProxyStack()}
	if runCheck("PRX002", ctx) != nil {
		t.Error("expected nil when proxy is nil")
	}
}

// ---- PRX003 ----

func TestPRX003_Critical_DashboardExposed(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeProxyStack()}
	findings := runCheck("PRX003", ctx)

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
}

func TestPRX003_Pass_DashboardNotExposed(t *testing.T) {
	stack := &model.Stack{
		Proxy: &model.ProxyConfig{
			Kind:             model.ProxyTraefik,
			DashboardExposed: false,
		},
	}
	ctx := &model.ScanContext{Stack: stack}
	findings := runCheck("PRX003", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestPRX003_NilProxy_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: nilProxyStack()}
	if runCheck("PRX003", ctx) != nil {
		t.Error("expected nil when proxy is nil")
	}
}

// ---- PRX004 ----

func TestPRX004_FlagsMissingSecurityHeaders(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeProxyStack()}
	findings := runCheck("PRX004", ctx)

	// Only the "app.x.com" route lacks security headers.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityInfo {
		t.Errorf("expected Info, got %v", f.Severity)
	}
	if f.Resource != "app.x.com" {
		t.Errorf("expected resource 'app.x.com', got %q", f.Resource)
	}
}

func TestPRX004_NilProxy_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: nilProxyStack()}
	if runCheck("PRX004", ctx) != nil {
		t.Error("expected nil when proxy is nil")
	}
}

// ---- PRX005 ----

func TestPRX005_FlagsWildcardRoute(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeProxyStack()}
	findings := runCheck("PRX005", ctx)

	// Only the "*.x.com" route is wildcard.
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", f.Severity)
	}
	if f.Resource != "*.x.com" {
		t.Errorf("expected resource '*.x.com', got %q", f.Resource)
	}
}

func TestPRX005_NilProxy_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: nilProxyStack()}
	if runCheck("PRX005", ctx) != nil {
		t.Error("expected nil when proxy is nil")
	}
}

func TestPRX005_Pass_NoWildcard(t *testing.T) {
	stack := &model.Stack{
		Proxy: &model.ProxyConfig{
			Kind: model.ProxyTraefik,
			Routes: []model.ProxyRoute{
				{Host: "app.x.com", Service: "app", TLS: true, HasAuth: true, SecurityHeaders: true, Wildcard: false},
			},
		},
	}
	ctx := &model.ScanContext{Stack: stack}
	findings := runCheck("PRX005", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

// ---- PRX006 ----

func TestPRX006_Critical_NPM(t *testing.T) {
	stack := &model.Stack{
		Proxy: &model.ProxyConfig{
			Kind: model.ProxyNPM,
		},
	}
	ctx := &model.ScanContext{Stack: stack}
	findings := runCheck("PRX006", ctx)
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
}

func TestPRX006_Pass_Traefik(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeProxyStack()} // Kind == traefik
	findings := runCheck("PRX006", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding for non-NPM proxy, got %v", findings)
	}
}

func TestPRX006_NilProxy_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: nilProxyStack()}
	if runCheck("PRX006", ctx) != nil {
		t.Error("expected nil when proxy is nil")
	}
}
