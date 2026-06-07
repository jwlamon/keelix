package catalog

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestEveryEntryHasValidBaseImpact(t *testing.T) {
	for _, e := range All() {
		if e.BaseImpact <= 0 || e.BaseImpact > 10 {
			t.Errorf("%s: BaseImpact = %v, want in (0,10]", e.ID, e.BaseImpact)
		}
	}
}

func TestFatalEntriesAreImpactful(t *testing.T) {
	for _, e := range All() {
		if e.Fatal && e.BaseImpact < 8 {
			t.Errorf("%s: Fatal entry has BaseImpact %v, want >= 8", e.ID, e.BaseImpact)
		}
	}
}

func TestAIAgentAndMCPEntriesExist(t *testing.T) {
	want := []struct {
		id        string
		fatal     bool
		minImpact float64
	}{
		{"AGT001", false, 8.5},
		{"AGT002", true, 9.5},
		{"AGT003", false, 7.0},
		{"AGT004", false, 6.0},
		{"AGT005", false, 5.0},
		{"AGT006", true, 9.0},
		{"AGT007", false, 8.0},
		{"AGT008", false, 6.5},
		{"AGT009", false, 6.0},
		{"AGT010", false, 5.5},
		{"MCP001", false, 8.0},
		{"MCP002", false, 5.5},
		{"MCP003", false, 6.0},
		{"MCP004", true, 9.0},
		{"MCP005", false, 7.5},
		{"MCP006", false, 5.5},
		{"MCP007", false, 9.0},
		{"MCP008", false, 5.0},
		{"MCP009", false, 8.5},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Fatal != w.fatal {
			t.Errorf("%s: Fatal = %v, want %v", w.id, e.Fatal, w.fatal)
		}
		if e.BaseImpact != w.minImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.minImpact)
		}
	}
}

func TestAIAgentAndMCPEntriesHaveCorrectGroups(t *testing.T) {
	for _, id := range []string{"AGT001", "AGT002", "AGT003", "AGT004", "AGT005",
		"AGT006", "AGT007", "AGT008", "AGT009", "AGT010"} {
		e, ok := entries[id]
		if !ok {
			t.Errorf("%s: missing", id)
			continue
		}
		if e.Group != model.GroupAIAgent {
			t.Errorf("%s: Group = %q, want GroupAIAgent", id, e.Group)
		}
	}
	for _, id := range []string{"MCP001", "MCP002", "MCP003", "MCP004", "MCP005",
		"MCP006", "MCP007", "MCP008", "MCP009"} {
		e, ok := entries[id]
		if !ok {
			t.Errorf("%s: missing", id)
			continue
		}
		if e.Group != model.GroupMCP {
			t.Errorf("%s: Group = %q, want GroupMCP", id, e.Group)
		}
	}
}

func TestCatalogVersion(t *testing.T) {
	if CatalogVersion != "2.4.0" {
		t.Errorf("CatalogVersion = %q, want 2.4.0", CatalogVersion)
	}
}

// TestSP4SupplyChainEntriesExist asserts the SP4 catalog additions.
//
// SUP003 is a non-Fatal Critical with BaseImpact 9.0 (SF-3): Fatal escalation
// is conditional and handled by score.applyKEVFatal, which promotes a KEV
// finding to Fatal only when ExposureClass.CanCapRed() — a KEV on a
// localhost-only service stays a high-weight non-fatal contributor.
// SUP004 is a non-fatal Warning. Both live in GroupSupplyChain.
func TestSP4SupplyChainEntriesExist(t *testing.T) {
	want := []struct {
		id         string
		severity   model.Severity
		baseImpact float64
		fatal      bool
	}{
		{"SUP003", model.SeverityCritical, 9.0, false}, // SF-3: Fatal=false; applyKEVFatal handles conditional escalation
		{"SUP004", model.SeverityWarning, 5.0, false},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != model.GroupSupplyChain {
			t.Errorf("%s: Group = %q, want GroupSupplyChain", w.id, e.Group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
		if e.Fatal != w.fatal {
			t.Errorf("%s: Fatal = %v, want %v", w.id, e.Fatal, w.fatal)
		}
		if len(e.Controls) == 0 {
			t.Errorf("%s: has no Controls", w.id)
		}
	}
}

func TestHSTSSHEntriesExist(t *testing.T) {
	want := []struct {
		id         string
		severity   model.Severity
		baseImpact float64
		fatal      bool
	}{
		{"HST001", model.SeverityWarning, 5.5, false},
		{"HST002", model.SeverityWarning, 6.0, false},
		{"HST003", model.SeverityCritical, 8.5, true},
		{"HST004", model.SeverityInfo, 3.0, false},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != model.GroupHost {
			t.Errorf("%s: Group = %q, want GroupHost", w.id, e.Group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
		if e.Fatal != w.fatal {
			t.Errorf("%s: Fatal = %v, want %v", w.id, e.Fatal, w.fatal)
		}
	}
}

func TestCislBuildsCISLinuxControlRef(t *testing.T) {
	ref := cisl("5.1.1", "SSH PermitRootLogin disabled")
	if ref.Framework != "CIS-Linux" {
		t.Fatalf("cisl Framework = %q, want %q", ref.Framework, "CIS-Linux")
	}
	if ref.ID != "5.1.1" {
		t.Fatalf("cisl ID = %q, want %q", ref.ID, "5.1.1")
	}
	if ref.Title != "SSH PermitRootLogin disabled" {
		t.Fatalf("cisl Title = %q, want %q", ref.Title, "SSH PermitRootLogin disabled")
	}
}

func TestHST003IsFatal(t *testing.T) {
	e, ok := entries["HST003"]
	if !ok {
		t.Fatal("HST003 missing from catalog")
	}
	if !e.Fatal {
		t.Error("HST003: Fatal = false, want true")
	}
	if e.BaseImpact != 8.5 {
		t.Errorf("HST003: BaseImpact = %v, want 8.5", e.BaseImpact)
	}
}

func TestHSTBruteForceAndPatchEntriesExist(t *testing.T) {
	want := []struct {
		id         string
		severity   model.Severity
		baseImpact float64
	}{
		{"HST005", model.SeverityInfo, 2.5},
		{"HST010", model.SeverityWarning, 5.0},
		{"HST011", model.SeverityCritical, 7.0},
		{"HST012", model.SeverityInfo, 2.5},
		{"HST013", model.SeverityInfo, 2.5},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != model.GroupHost {
			t.Errorf("%s: Group = %q, want GroupHost", w.id, e.Group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
	}
}

func TestHSTAccountEntriesExist(t *testing.T) {
	want := []struct {
		id         string
		severity   model.Severity
		baseImpact float64
	}{
		{"HST020", model.SeverityWarning, 6.0},
		{"HST021", model.SeverityCritical, 7.5},
		{"HST022", model.SeverityCritical, 7.5},
		{"HST023", model.SeverityWarning, 6.0},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != model.GroupHost {
			t.Errorf("%s: Group = %q, want GroupHost", w.id, e.Group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
	}
}

func TestHSTFirewallSysctlEncryptionEntriesExist(t *testing.T) {
	want := []struct {
		id         string
		severity   model.Severity
		baseImpact float64
	}{
		{"HST030", model.SeverityWarning, 5.5},
		{"HST040", model.SeverityInfo, 3.0},
		{"HST041", model.SeverityInfo, 2.0},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != model.GroupHost {
			t.Errorf("%s: Group = %q, want GroupHost", w.id, e.Group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
	}
}

func TestL2EntriesExist(t *testing.T) {
	want := []struct {
		id         string
		group      model.CheckGroup
		severity   model.Severity
		baseImpact float64
		fatal      bool
	}{
		{"FW005", model.GroupFirewall, model.SeverityCritical, 9.5, true},
		{"FW006", model.GroupFirewall, model.SeverityCritical, 9.0, true},
		{"HRD009", model.GroupHardening, model.SeverityWarning, 6.5, false},
		{"HRD010", model.GroupHardening, model.SeverityWarning, 7.0, false},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != w.group {
			t.Errorf("%s: Group = %q, want %q", w.id, e.Group, w.group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
		if e.Fatal != w.fatal {
			t.Errorf("%s: Fatal = %v, want %v", w.id, e.Fatal, w.fatal)
		}
	}
}

func TestSP3ServiceEntriesExist(t *testing.T) {
	want := []struct {
		id         string
		severity   model.Severity
		baseImpact float64
		fatal      bool
	}{
		{"SVC001", model.SeverityCritical, 9.0, true},
		{"SVC002", model.SeverityCritical, 9.0, true},
		{"SVC003", model.SeverityCritical, 9.0, true},
		{"SVC004", model.SeverityCritical, 8.5, true},
		{"SVC010", model.SeverityCritical, 8.0, true},
		{"SVC011", model.SeverityWarning, 6.0, false},
		{"SVC020", model.SeverityWarning, 6.5, false},
		{"SVC021", model.SeverityWarning, 5.5, false},
		{"SVC030", model.SeverityCritical, 8.5, true},
		{"SVC031", model.SeverityWarning, 6.5, false},
		{"SVC032", model.SeverityCritical, 8.5, true},
		{"SVC040", model.SeverityWarning, 6.0, false},
		{"SVC041", model.SeverityWarning, 6.5, false},
		{"SVC050", model.SeverityCritical, 8.5, true},
		{"SVC051", model.SeverityWarning, 6.0, false},
		{"SVC052", model.SeverityWarning, 5.5, false},
		{"SVC060", model.SeverityCritical, 8.0, true},
	}
	for _, w := range want {
		e, ok := entries[w.id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", w.id)
			continue
		}
		if e.Group != model.GroupService {
			t.Errorf("%s: Group = %q, want GroupService", w.id, e.Group)
		}
		if e.Severity != w.severity {
			t.Errorf("%s: Severity = %q, want %q", w.id, e.Severity, w.severity)
		}
		if e.BaseImpact != w.baseImpact {
			t.Errorf("%s: BaseImpact = %v, want %v", w.id, e.BaseImpact, w.baseImpact)
		}
		if e.Fatal != w.fatal {
			t.Errorf("%s: Fatal = %v, want %v", w.id, e.Fatal, w.fatal)
		}
		if len(e.Rationale) < 20 {
			t.Errorf("%s: Rationale too short (got %d chars)", w.id, len(e.Rationale))
		}
		if len(e.Controls) == 0 {
			t.Errorf("%s: has no Controls", w.id)
		}
	}
}

// TestR4_3_SVC010_SVC060_AreFatal asserts that SVC010 and SVC060 are marked Fatal
// because they are SeverityCritical SVC checks (rule: every SeverityCritical SVC/FW
// config check is Fatal). Added for R4-3 remediation.
func TestR4_3_SVC010_SVC060_AreFatal(t *testing.T) {
	for _, id := range []string{"SVC010", "SVC060"} {
		e, ok := entries[id]
		if !ok {
			t.Errorf("%s: entry missing from catalog", id)
			continue
		}
		if e.Severity != model.SeverityCritical {
			t.Errorf("%s: Severity = %q, want Critical", id, e.Severity)
		}
		if !e.Fatal {
			t.Errorf("%s: Fatal = false, want true (rule: every SeverityCritical SVC/FW check is Fatal)", id)
		}
		if e.BaseImpact < 8.0 {
			t.Errorf("%s: BaseImpact = %v, want >= 8.0 for a fatal entry", id, e.BaseImpact)
		}
	}
}

// TestR4_3_AllCriticalSVCFWAreFatal asserts that every SeverityCritical entry in
// GroupService or GroupFirewall is marked Fatal (the stated catalog rule).
func TestR4_3_AllCriticalSVCFWAreFatal(t *testing.T) {
	for _, e := range All() {
		if e.Severity != model.SeverityCritical {
			continue
		}
		if e.Group != model.GroupService && e.Group != model.GroupFirewall {
			continue
		}
		if !e.Fatal {
			t.Errorf("%s (%s/%s): Fatal = false, violates rule: every SeverityCritical SVC/FW check must be Fatal",
				e.ID, e.Group, e.Severity)
		}
	}
}

func TestHSTEntriesHaveCorrectGroups(t *testing.T) {
	hstIDs := []string{
		"HST001", "HST002", "HST003", "HST004", "HST005",
		"HST010", "HST011", "HST012", "HST013",
		"HST020", "HST021", "HST022", "HST023",
		"HST030", "HST040", "HST041",
	}
	for _, id := range hstIDs {
		e, ok := entries[id]
		if !ok {
			t.Errorf("%s: missing from catalog", id)
			continue
		}
		if e.Group != model.GroupHost {
			t.Errorf("%s: Group = %q, want GroupHost", id, e.Group)
		}
	}
}
