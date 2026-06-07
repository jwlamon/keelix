package dns_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/dns"
	"github.com/jwlamon/keelix/internal/model"
)

func runCheck(id string, ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c.Run(ctx)
		}
	}
	panic("check not registered: " + id)
}

func makeProbeWithRecords(records ...model.DNSRecord) *model.ProbeResult {
	return &model.ProbeResult{
		Host:       "example.com",
		DNSRecords: records,
		Reachable:  map[int]model.PortProbe{},
	}
}

// ---- DNS001 ----

func TestDNS001_Info_WildcardRecord(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithRecords(
			model.DNSRecord{Name: "*.x.com", Type: "A", Value: "1.2.3.4", Wildcard: true},
			model.DNSRecord{Name: "old.x.com", Type: "CNAME", Value: "gone.example.com", Dangling: true},
		),
	}

	findings := runCheck("DNS001", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityInfo {
		t.Errorf("expected Info, got %v", f.Severity)
	}
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
	if f.Resource != "*.x.com" {
		t.Errorf("expected resource '*.x.com', got %q", f.Resource)
	}
}

func TestDNS001_Pass_NoWildcard(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithRecords(
			model.DNSRecord{Name: "app.x.com", Type: "A", Value: "1.2.3.4", Wildcard: false},
		),
	}
	findings := runCheck("DNS001", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestDNS001_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	if runCheck("DNS001", ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- DNS002 ----

func TestDNS002_Warning_DanglingRecord(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithRecords(
			model.DNSRecord{Name: "*.x.com", Type: "A", Value: "1.2.3.4", Wildcard: true},
			model.DNSRecord{Name: "old.x.com", Type: "CNAME", Value: "gone.example.com", Dangling: true},
		),
	}

	findings := runCheck("DNS002", ctx)
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

func TestDNS002_Pass_NoDangling(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: &model.Stack{},
		Probe: makeProbeWithRecords(
			model.DNSRecord{Name: "app.x.com", Type: "A", Value: "1.2.3.4", Dangling: false},
		),
	}
	findings := runCheck("DNS002", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestDNS002_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{}}
	if runCheck("DNS002", ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- Combined scenario from spec ----

// TestDNSCombined_SpecScenario verifies the full spec scenario:
// Probe DNSRecords [{Name:"*.x.com",Wildcard:true},{Name:"old.x.com",Type:"CNAME",Dangling:true}]
// -> DNS001 info, DNS002 warning.
func TestDNSCombined_SpecScenario(t *testing.T) {
	probe := makeProbeWithRecords(
		model.DNSRecord{Name: "*.x.com", Type: "A", Value: "1.2.3.4", Wildcard: true},
		model.DNSRecord{Name: "old.x.com", Type: "CNAME", Value: "gone.example.com", Dangling: true},
	)
	ctx := &model.ScanContext{Stack: &model.Stack{}, Probe: probe}

	dns001Findings := runCheck("DNS001", ctx)
	if len(dns001Findings) != 1 || dns001Findings[0].Severity != model.SeverityInfo {
		t.Errorf("DNS001: expected 1 info finding, got %v", dns001Findings)
	}

	dns002Findings := runCheck("DNS002", ctx)
	if len(dns002Findings) != 1 || dns002Findings[0].Severity != model.SeverityWarning {
		t.Errorf("DNS002: expected 1 warning finding, got %v", dns002Findings)
	}
}
