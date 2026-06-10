package collect

// TestRFX_FW005_ParserFed contains the MANDATORY PARSER-FED regression tests
// for FW005 (Docker daemon TCP API exposure). They run the real parseDockerDaemon
// parser over committed fixtures (testdata/docker_daemon_*.json) and feed the
// resulting ConfigFact directly to fw005.Run() — the only form that guards
// against parser↔check contract mismatches that synthetic-signal tests can never
// catch.
//
// SchemaID contract: "docker-daemon", Values key: "hosts" (comma-joined list).
//
// FIX-5 DISCIPLINE NOTE: tests that cover the ExposureClass fix (tailnet/CGNAT
// producing ExposureOverlay rather than ExposureInternet) MUST route the fixture
// through collectConfigInternal so the redaction stage runs — a synthetic
// hand-built ConfigFact that skips the parser+redact pipeline does NOT satisfy
// the PARSER-FED requirement for the ExposureClass correctness fix.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/firewall"
	"github.com/jakelamon/keelix/internal/model"
)

// TestRFX_FW005_TCP_Fires verifies the end-to-end pipeline:
//
//	parseDockerDaemon over testdata/docker_daemon_tcp.json
//	  -> ConfigFact{SchemaID:"docker-daemon", Values["hosts"]: "tcp://0.0.0.0:2375,..."}
//	  -> FW005.Run() on Linux
//	  -> non-passing Critical finding
func TestRFX_FW005_TCP_Fires(t *testing.T) {
	c := findRegisteredCheck(t, "FW005")

	b := mustReadTestdata(t, "docker_daemon_tcp.json")
	vals, schemaID, known := parseDockerDaemon(b)
	if !known {
		t.Fatalf("parseDockerDaemon: known=false on docker_daemon_tcp.json fixture")
	}
	if schemaID != "docker-daemon" {
		t.Fatalf("parseDockerDaemon: schemaID=%q, want docker-daemon", schemaID)
	}
	// Verify the parser emitted a non-empty hosts value with the tcp:// entry.
	if vals["hosts"] == "" {
		t.Fatalf("parseDockerDaemon: hosts=%q, want non-empty — fixture has tcp://0.0.0.0:2375", vals["hosts"])
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "docker_daemon_tcp.json"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("FW005: no findings returned for tcp://0.0.0.0:2375 fixture")
	}
	f := findings[0]
	if f.Passed {
		t.Fatalf("FW005: expected failing finding for non-loopback TCP host, got pass\nValues: %v", vals)
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("FW005: want Critical severity, got %v", f.Severity)
	}
	// Wildcard bind must produce ExposureInternet (FIX-5 regression guard).
	if f.ExposureClass != model.ExposureInternet {
		t.Errorf("FW005: wildcard bind 0.0.0.0 must produce ExposureInternet; got %v", f.ExposureClass)
	}
}

// TestRFX_FW005_Loopback_Pass verifies that a loopback-only TCP bind
// (tcp://127.0.0.1:2375) does NOT fire FW005.
func TestRFX_FW005_Loopback_Pass(t *testing.T) {
	c := findRegisteredCheck(t, "FW005")

	b := mustReadTestdata(t, "docker_daemon_loopback.json")
	vals, schemaID, known := parseDockerDaemon(b)
	if !known {
		t.Fatalf("parseDockerDaemon: known=false on docker_daemon_loopback.json fixture")
	}
	if schemaID != "docker-daemon" {
		t.Fatalf("parseDockerDaemon: schemaID=%q, want docker-daemon", schemaID)
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "docker_daemon_loopback.json"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("FW005: no findings returned for loopback fixture")
	}
	f := findings[0]
	if !f.Passed {
		t.Fatalf("FW005: expected pass for loopback-only TCP bind, got fail\nValues: %v\nfinding: %+v", vals, f)
	}
}

// TestRFX_FW005_SockOnly_Pass verifies that a socket-only daemon.json
// (no tcp:// entry) produces a passing finding.
func TestRFX_FW005_SockOnly_Pass(t *testing.T) {
	c := findRegisteredCheck(t, "FW005")

	b := mustReadTestdata(t, "docker_daemon_sock.json")
	vals, schemaID, known := parseDockerDaemon(b)
	if !known {
		t.Fatalf("parseDockerDaemon: known=false on docker_daemon_sock.json fixture")
	}
	if schemaID != "docker-daemon" {
		t.Fatalf("parseDockerDaemon: schemaID=%q, want docker-daemon", schemaID)
	}

	fact := model.ConfigFact{
		SchemaID:    schemaID,
		SchemaKnown: true,
		Source:      filepath.Join("testdata", "docker_daemon_sock.json"),
		Values:      vals,
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("FW005: no findings returned for sock-only fixture")
	}
	f := findings[0]
	if !f.Passed {
		t.Fatalf("FW005: expected pass for unix-socket-only daemon, got fail\nValues: %v\nfinding: %+v", vals, f)
	}
}

// TestRFX_FW005_NoCollector_NotAssessed verifies that FW005 returns
// StatusNotAssessed when Collector is nil (no collect run, e.g. cloud scan).
func TestRFX_FW005_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "FW005")

	ctx := &model.ScanContext{Collector: nil}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("FW005: no findings returned for nil collector")
	}
	f := findings[0]
	if f.Status != model.StatusNotAssessed {
		t.Errorf("FW005: want StatusNotAssessed for nil collector, got %v", f.Status)
	}
}

// TestRFX_FW005_Darwin_NotAssessed verifies that FW005 returns
// StatusNotAssessed on macOS (Docker daemon TCP check is Linux-only).
func TestRFX_FW005_Darwin_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "FW005")

	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "darwin"},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("FW005: no findings returned for darwin platform")
	}
	f := findings[0]
	if f.Status != model.StatusNotAssessed {
		t.Errorf("FW005: want StatusNotAssessed on darwin, got %v", f.Status)
	}
}

// TestRFX_FW005_TailnetHost_ExposureOverlay is the MANDATORY PARSER-FED test for
// the FIX-5 ExposureClass correctness fix on Path 2 (ConfigFact / daemon.json).
//
// It verifies that a daemon.json binding dockerd to a CGNAT/tailnet address
// (100.64.x.x) produces ExposureOverlay, not the previously hardcoded
// ExposureInternet ("false RED" defect). The fixture is routed through
// collectConfigInternal so the full parser+redact pipeline runs — a hand-built
// synthetic ConfigFact is explicitly not sufficient per the SP3 discipline.
//
// Fixture: testdata/docker_daemon_tailnet.json — {"hosts":["tcp://100.64.1.5:2375","unix:///var/run/docker.sock"]}
func TestRFX_FW005_TailnetHost_ExposureOverlay(t *testing.T) {
	c := findRegisteredCheck(t, "FW005")

	// Route through collectConfigInternal: real parser + redactConfigValues.
	fixturePath := filepath.Join("testdata", "docker_daemon_tailnet.json")
	fact := collectConfigInternal(fixturePath, parseDockerDaemon)
	if !fact.SchemaKnown {
		t.Fatalf("collectConfigInternal: SchemaKnown=false for docker_daemon_tailnet.json; values: %v", fact.Values)
	}
	if fact.SchemaID != "docker-daemon" {
		t.Fatalf("collectConfigInternal: SchemaID=%q, want docker-daemon", fact.SchemaID)
	}
	if fact.Values["hosts"] == "" {
		t.Fatalf("collectConfigInternal: hosts=%q, want non-empty — fixture has tcp://100.64.1.5:2375", fact.Values["hosts"])
	}

	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := c.Run(ctx)

	if len(findings) == 0 {
		t.Fatal("FW005: no findings returned for tailnet daemon.json fixture")
	}
	f := findings[0]
	// Must still fire — tailnet docker API exposure is a finding.
	if f.Passed {
		t.Fatalf("FW005: tailnet dockerd (daemon.json) must produce a failing finding; got pass\nValues: %v", fact.Values)
	}
	// FIX-5: CGNAT/tailnet host must produce ExposureOverlay, not ExposureInternet.
	if f.ExposureClass == model.ExposureInternet {
		t.Errorf("FW005: tailnet bind 100.64.1.5 in daemon.json must NOT produce ExposureInternet (false RED); got %v", f.ExposureClass)
	}
	if f.ExposureClass != model.ExposureOverlay {
		t.Errorf("FW005: tailnet bind 100.64.1.5 in daemon.json must produce ExposureOverlay; got %v", f.ExposureClass)
	}
}
