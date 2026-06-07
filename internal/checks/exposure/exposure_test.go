package exposure_test

import (
	"testing"

	// blank imports to trigger init() registrations
	_ "github.com/jwlamon/keelix/internal/checks/exposure"
	"github.com/jwlamon/keelix/internal/model"
)

// makeStack builds a minimal stack with one service "db" publishing 5432.
func makeStack() *model.Stack {
	return &model.Stack{
		Services: []*model.Service{
			{
				Name:  "db",
				Image: "postgres:16",
				Ports: []model.PortMapping{
					{HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
				},
			},
		},
	}
}

// makeProbe builds a ProbeResult with the given ports open.
func makeProbe(openPorts ...int) *model.ProbeResult {
	r := make(map[int]model.PortProbe, len(openPorts))
	for _, p := range openPorts {
		r[p] = model.PortProbe{Port: p, Open: true}
	}
	return &model.ProbeResult{
		Host:         "example.com",
		VantagePoint: "scanner.example.net",
		Reachable:    r,
	}
}

// ---- EXP001 ----

func TestEXP001_Critical_SensitiveReachable(t *testing.T) {
	ctx := &model.ScanContext{
		Stack:    makeStack(),
		Probe:    makeProbe(5432),
		Intended: map[int]bool{},
	}
	check := &exp001wrapper{}
	findings := check.Run(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected Critical, got %v", f.Severity)
	}
	if f.Service != "db" {
		t.Errorf("expected service 'db', got %q", f.Service)
	}
	if f.Passed {
		t.Error("finding should not be marked passed")
	}
}

func TestEXP001_Pass_WhenIntended(t *testing.T) {
	ctx := &model.ScanContext{
		Stack:    makeStack(),
		Probe:    makeProbe(5432),
		Intended: map[int]bool{5432: true},
	}
	check := &exp001wrapper{}
	findings := check.Run(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 (pass) finding, got %d", len(findings))
	}
	if !findings[0].Passed {
		t.Error("expected a passing finding when port is intended")
	}
}

func TestEXP001_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{
		Stack:    makeStack(),
		Probe:    nil,
		Intended: map[int]bool{},
	}
	check := &exp001wrapper{}
	findings := check.Run(ctx)
	if findings != nil {
		t.Errorf("expected nil when probe is nil, got %v", findings)
	}
}

// ---- EXP002 ----

func TestEXP002_Warning_UndeclaredReachable(t *testing.T) {
	// Port 9999 is reachable but not declared in Compose and not sensitive, not 80/443.
	ctx := &model.ScanContext{
		Stack:    makeStack(),
		Probe:    makeProbe(9999),
		Intended: map[int]bool{},
	}
	check := &exp002wrapper{}
	findings := check.Run(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", findings[0].Severity)
	}
}

func TestEXP002_Pass_DeclaredOnly(t *testing.T) {
	// Port 5432 is declared in Compose — not an undeclared surprise.
	ctx := &model.ScanContext{
		Stack:    makeStack(),
		Probe:    makeProbe(5432),
		Intended: map[int]bool{},
	}
	check := &exp002wrapper{}
	findings := check.Run(ctx)
	// EXP002 should pass because the only reachable port is either declared or sensitive (covered by EXP001)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected a single pass finding, got %v", findings)
	}
}

func TestEXP002_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeStack(), Probe: nil}
	check := &exp002wrapper{}
	if check.Run(ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- EXP003 ----

func TestEXP003_Info_DeclaredNotReachable(t *testing.T) {
	// Stack declares 5432 but the probe shows it is NOT open.
	ctx := &model.ScanContext{
		Stack: makeStack(),
		Probe: makeProbe(), // nothing reachable
	}
	check := &exp003wrapper{}
	findings := check.Run(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("expected Info, got %v", findings[0].Severity)
	}
	if findings[0].Passed {
		t.Error("finding should not be marked passed")
	}
}

func TestEXP003_Pass_AllDeclaredReachable(t *testing.T) {
	ctx := &model.ScanContext{
		Stack: makeStack(),
		Probe: makeProbe(5432),
	}
	check := &exp003wrapper{}
	findings := check.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestEXP003_NilProbe_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeStack(), Probe: nil}
	check := &exp003wrapper{}
	if check.Run(ctx) != nil {
		t.Error("expected nil when probe is nil")
	}
}

// ---- wrappers to avoid importing the unexported structs ----
// We reach into the registered checks via the model registry instead.

type exp001wrapper struct{}

func (w *exp001wrapper) Run(ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == "EXP001" {
			return c.Run(ctx)
		}
	}
	panic("EXP001 not registered")
}

type exp002wrapper struct{}

func (w *exp002wrapper) Run(ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == "EXP002" {
			return c.Run(ctx)
		}
	}
	panic("EXP002 not registered")
}

type exp003wrapper struct{}

func (w *exp003wrapper) Run(ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == "EXP003" {
			return c.Run(ctx)
		}
	}
	panic("EXP003 not registered")
}
