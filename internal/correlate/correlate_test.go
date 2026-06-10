package correlate

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

// testStack builds the stack described in the spec:
//   - service "db"  image "postgres:16"  port 5432->5432 (all interfaces)
//   - service "web" image "nginx"        port 443->443   (all interfaces)
func testStack() *model.Stack {
	return &model.Stack{
		Services: []*model.Service{
			{
				Name:  "db",
				Image: "postgres:16",
				Ports: []model.PortMapping{
					{HostIP: "", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
				},
			},
			{
				Name:  "web",
				Image: "nginx",
				Ports: []model.PortMapping{
					{HostIP: "", HostPort: 443, ContainerPort: 443, Protocol: "tcp"},
				},
			},
		},
	}
}

// testProbe builds a ProbeResult with ports 5432, 443, and 2222 open.
func testProbe() *model.ProbeResult {
	return &model.ProbeResult{
		Reachable: map[int]model.PortProbe{
			5432: {Port: 5432, Open: true},
			443:  {Port: 443, Open: true},
			2222: {Port: 2222, Open: true},
		},
	}
}

// TestBuildIntended verifies that 443 (nginx) is marked intended and 5432 (postgres) is not.
func TestBuildIntended(t *testing.T) {
	s := testStack()
	intended := BuildIntended(s, model.ScanOptions{})

	if !intended[443] {
		t.Error("expected 443 to be intended (nginx public port) but it was not")
	}
	if intended[5432] {
		t.Error("expected 5432 NOT to be intended (postgres is a sensitive port) but it was marked intended")
	}
}

// TestBuildIntendedWithExplicit verifies that IntendedPorts seeds the map.
func TestBuildIntendedWithExplicit(t *testing.T) {
	s := testStack()
	intended := BuildIntended(s, model.ScanOptions{IntendedPorts: []int{8080, 9090}})

	if !intended[8080] {
		t.Error("expected 8080 (explicit) to be intended")
	}
	if !intended[9090] {
		t.Error("expected 9090 (explicit) to be intended")
	}
}

// TestBuildIntendedNilStack verifies BuildIntended never panics or returns nil on a nil stack.
func TestBuildIntendedNilStack(t *testing.T) {
	intended := BuildIntended(nil, model.ScanOptions{})
	if intended == nil {
		t.Error("BuildIntended must not return nil")
	}
}

// TestCorrelate verifies the main happy-path assertions from the spec.
func TestCorrelate(t *testing.T) {
	s := testStack()
	p := testProbe()

	r := Correlate(s, p)

	// --- 5432 must be in SensitiveExposed with Service "db" and Detail "PostgreSQL" ---
	found5432 := false
	for _, f := range r.SensitiveExposed {
		if f.Port == 5432 {
			found5432 = true
			if f.Service != "db" {
				t.Errorf("SensitiveExposed[5432].Service = %q, want \"db\"", f.Service)
			}
			if f.Detail != "PostgreSQL" {
				t.Errorf("SensitiveExposed[5432].Detail = %q, want \"PostgreSQL\"", f.Detail)
			}
		}
	}
	if !found5432 {
		t.Error("expected 5432 in SensitiveExposed but it was not found")
	}

	// --- 443 must be in Expected with Service "web" ---
	found443 := false
	for _, f := range r.Expected {
		if f.Port == 443 {
			found443 = true
			if f.Service != "web" {
				t.Errorf("Expected[443].Service = %q, want \"web\"", f.Service)
			}
		}
	}
	if !found443 {
		t.Error("expected 443 in Expected but it was not found")
	}

	// --- 2222 must be in Surprises ---
	found2222 := false
	for _, f := range r.Surprises {
		if f.Port == 2222 {
			found2222 = true
		}
	}
	if !found2222 {
		t.Error("expected 2222 in Surprises but it was not found")
	}

	// --- Declared must contain 5432 and 443 ---
	declaredSet := make(map[int]bool)
	for _, p := range r.Declared {
		declaredSet[p] = true
	}
	if !declaredSet[5432] {
		t.Error("expected 5432 in Declared")
	}
	if !declaredSet[443] {
		t.Error("expected 443 in Declared")
	}

	// --- Reachable must contain 5432, 443, and 2222 ---
	reachableSet := make(map[int]bool)
	for _, p := range r.Reachable {
		reachableSet[p] = true
	}
	for _, want := range []int{5432, 443, 2222} {
		if !reachableSet[want] {
			t.Errorf("expected %d in Reachable", want)
		}
	}
}

// TestCorrelateNilProbe verifies that p==nil returns empty Reachable and Blocked without panic.
func TestCorrelateNilProbe(t *testing.T) {
	s := testStack()
	r := Correlate(s, nil)

	if r == nil {
		t.Fatal("Correlate returned nil")
	}
	if len(r.Reachable) != 0 {
		t.Errorf("expected empty Reachable with nil probe, got %v", r.Reachable)
	}
	if len(r.Blocked) != 0 {
		t.Errorf("expected empty Blocked with nil probe, got %v", r.Blocked)
	}
	// Declared should still be populated from stack.
	if len(r.Declared) == 0 {
		t.Error("expected non-empty Declared even with nil probe")
	}
}

// TestCorrelateString verifies String() does not panic.
func TestCorrelateString(t *testing.T) {
	r := Correlate(testStack(), testProbe())
	s := r.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
}

// TestSortOrder verifies lists are returned in ascending port order.
func TestSortOrder(t *testing.T) {
	r := Correlate(testStack(), testProbe())

	for i := 1; i < len(r.Declared); i++ {
		if r.Declared[i] < r.Declared[i-1] {
			t.Errorf("Declared not sorted: %v", r.Declared)
			break
		}
	}
	for i := 1; i < len(r.Reachable); i++ {
		if r.Reachable[i] < r.Reachable[i-1] {
			t.Errorf("Reachable not sorted: %v", r.Reachable)
			break
		}
	}
}
