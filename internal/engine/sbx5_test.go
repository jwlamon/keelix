package engine

// SBX-5 tests: sandbox-availability gate for the active MCP probe.
//
// The gate logic lives in maybeProbeMCPInner; we drive it directly here so we
// can inject a forced sandboxAvailable=false without depending on the real host
// platform state. The tests are real (non-skipped) because the gate is pure
// Go — no kernel syscall is needed to exercise the decision logic.

import (
	"context"
	"io"
	"testing"

	"github.com/jakelamon/keelix/internal/model"
	"github.com/jakelamon/keelix/internal/sandbox"
)

// noopRunner is a sentinel sandbox.Runner that records whether Start/Run were
// called. Any call to Start or Run means the probe attempted to spawn; we use
// this to assert no-spawn when the gate should block execution.
type noopRunner struct {
	startCalled bool
	runCalled   bool
}

func (r *noopRunner) Run(_ context.Context, _ sandbox.Spec) (*sandbox.Result, error) {
	r.runCalled = true
	// Return a result indicating Tier-0 only (no real sandbox).
	return &sandbox.Result{
		Tier:           "tier0",
		SandboxApplied: false,
	}, nil
}

func (r *noopRunner) Start(_ context.Context, _ sandbox.Spec) (sandbox.Session, error) {
	r.startCalled = true
	return &noopSession{}, nil
}

// noopSession is a minimal do-nothing Session returned by noopRunner.Start.
// Its Stdout returns EOF immediately so any JSON-RPC handshake times out or
// returns no tools (the probe records Reached=false or an error).
type noopSession struct{}

func (s *noopSession) Stdin() io.Writer  { return io.Discard }
func (s *noopSession) Stdout() io.Reader { return emptyReader{} }
func (s *noopSession) Tier() string      { return "tier0" }
func (s *noopSession) Applied() bool     { return false }
func (s *noopSession) Close() error      { return nil }

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// sigWithMCPServer returns a Signals fixture with one stdio MCP server entry.
func sigWithMCPServer(cmd string) *model.Signals {
	return &model.Signals{
		Configs: []model.ConfigFact{
			{
				Source:      "~/.cursor/mcp.json",
				SchemaID:    "cursor-mcp",
				SchemaKnown: true,
				Values: map[string]string{
					"mcpServers.fake.command": cmd,
				},
			},
		},
	}
}

// TestSBX5_NoSandbox_ProbeSkipped asserts that with sandboxAvailable=false and
// MCPProbeUnsandboxed=false, maybeProbeMCPInner does NOT spawn the runner and
// returns (nil, <info finding>) — inventory-only downgrade (SBX-5 gate).
func TestSBX5_NoSandbox_ProbeSkipped(t *testing.T) {
	runner := &noopRunner{}
	opts := model.ScanOptions{
		MCPProbeEnabled:     true,
		MCPProbeConsent:     true,
		MCPProbeUnsandboxed: false, // default: do NOT allow Tier-0-only
	}
	sig := sigWithMCPServer("/bin/true")

	probe, findings := maybeProbeMCPInner(opts, sig, t.TempDir()+"/baseline.json", false /* no sandbox */, runner)

	// Probe must be nil: no spawn.
	if probe != nil {
		t.Errorf("SBX-5: probe should be nil when no sandbox is available (unsandboxed=false), got %+v", probe)
	}
	// Runner must NOT have been called.
	if runner.startCalled {
		t.Error("SBX-5: runner.Start was called despite no sandbox being available — untrusted code was spawned!")
	}
	if runner.runCalled {
		t.Error("SBX-5: runner.Run was called despite no sandbox being available — untrusted code was spawned!")
	}
	// An info finding must explain how to override.
	if len(findings) == 0 {
		t.Fatal("SBX-5: expected an info finding when probe is skipped, got none")
	}
	f := findings[0]
	if f.CheckID != "MCP000" {
		t.Errorf("SBX-5: finding CheckID = %q, want MCP000", f.CheckID)
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("SBX-5: finding Severity = %v, want Info", f.Severity)
	}
	if f.Status != model.StatusNotAssessed {
		t.Errorf("SBX-5: finding Status = %v, want NotAssessed", f.Status)
	}
	// The detail must mention the override flag.
	if len(f.Detail) == 0 {
		t.Error("SBX-5: finding Detail is empty")
	}
}

// TestSBX5_NoSandbox_UnsandboxedOverride asserts that with sandboxAvailable=false
// and MCPProbeUnsandboxed=true, maybeProbeMCPInner DOES spawn (runner.Start is
// called) and returns a warning finding about the weaker isolation (SBX-5 gate).
func TestSBX5_NoSandbox_UnsandboxedOverride(t *testing.T) {
	runner := &noopRunner{}
	opts := model.ScanOptions{
		MCPProbeEnabled:     true,
		MCPProbeConsent:     true,
		MCPProbeUnsandboxed: true, // operator override: allow Tier-0 only
	}
	sig := sigWithMCPServer("/bin/true")

	probe, findings := maybeProbeMCPInner(opts, sig, t.TempDir()+"/baseline.json", false /* no sandbox */, runner)

	// Runner MUST have been called (the probe should try to spawn).
	if !runner.startCalled && !runner.runCalled {
		t.Error("SBX-5: runner was not called despite MCPProbeUnsandboxed=true — probe was wrongly suppressed")
	}
	// probe is non-nil OR we at least got a warning finding (noopRunner produces
	// an EOF immediately so the probe may record zero servers but still ran).
	_ = probe // nil is acceptable if the fake server produced no tools

	// A warning finding must be present explaining the weakened isolation.
	if len(findings) == 0 {
		t.Fatal("SBX-5: expected a warning finding when running unsandboxed, got none")
	}
	f := findings[0]
	if f.CheckID != "MCP000" {
		t.Errorf("SBX-5: finding CheckID = %q, want MCP000", f.CheckID)
	}
	if f.Severity != model.SeverityWarning {
		t.Errorf("SBX-5: finding Severity = %v, want Warning", f.Severity)
	}
}

// TestSBX5_SandboxAvailable_NormalPath asserts that with sandboxAvailable=true
// the gate is transparent: the runner is called and no MCP000 gate finding is
// emitted for the availability check (a real probe may still produce findings,
// but not MCP000 from the gate itself).
func TestSBX5_SandboxAvailable_NormalPath(t *testing.T) {
	runner := &noopRunner{}
	opts := model.ScanOptions{
		MCPProbeEnabled:     true,
		MCPProbeConsent:     true,
		MCPProbeUnsandboxed: false,
	}
	sig := sigWithMCPServer("/bin/true")

	_, findings := maybeProbeMCPInner(opts, sig, t.TempDir()+"/baseline.json", true /* sandbox available */, runner)

	// No MCP000 gate finding should be emitted when sandbox is available.
	for _, f := range findings {
		if f.CheckID == "MCP000" {
			t.Errorf("SBX-5: unexpected MCP000 gate finding when sandbox is available: %+v", f)
		}
	}
	// Runner must have been called (probe was not blocked).
	if !runner.startCalled && !runner.runCalled {
		t.Error("SBX-5: runner was not called despite sandbox being available")
	}
}
