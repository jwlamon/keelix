package mcpprobe

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jakelamon/keelix/internal/sandbox"
)

// tierSession wraps a multiResponseSession (which answers a real initialize +
// tools/list over a working pipe) but lets the test control the values returned
// by Tier() and Applied(). This is the crux of the regression test: we drive
// the PRODUCTION newStdioClient/probeOne path (no setStdioClientSeam) through a
// real sandbox.Session whose Tier/Applied we dictate, then assert that probe.go
// — not a fake — performs the honest tier demotion.
type tierSession struct {
	*multiResponseSession
	tier    string
	applied bool
}

func (s *tierSession) Tier() string  { return s.tier }
func (s *tierSession) Applied() bool { return s.applied }

// tierRunner is a sandbox.Runner whose Start returns a tierSession answering a
// minimal initialize + tools/list, with caller-controlled Tier()/Applied(). It
// deliberately exercises the real newStdioClient path (the seam is NOT
// installed), so the SandboxTier/SandboxApplied values on the resulting probe
// come from probe.go's demotion block.
type tierRunner struct {
	responses []string
	tier      string
	applied   bool
}

func (r *tierRunner) Run(_ context.Context, _ sandbox.Spec) (*sandbox.Result, error) {
	return &sandbox.Result{Tier: r.tier, SandboxApplied: r.applied}, nil
}

func (r *tierRunner) Start(_ context.Context, _ sandbox.Spec) (sandbox.Session, error) {
	return &tierSession{
		multiResponseSession: newMultiResponseSession(r.responses),
		tier:                 r.tier,
		applied:              r.applied,
	}, nil
}

// minimalHandshakeResponses returns the two canned JSON-RPC responses that the
// production discover() flow consumes in order: initialize (id=1) and
// tools/list (id=2). The advertised protocol matches supportedProtocol so the
// handshake is accepted and Reached becomes true.
func minimalHandshakeResponses(t *testing.T) []string {
	t.Helper()
	initResp, err := json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      1,
		Result:  json.RawMessage(`{"protocolVersion":"` + supportedProtocol + `","capabilities":{},"serverInfo":{"name":"fake","version":"0"}}`),
	})
	if err != nil {
		t.Fatalf("marshal initResp: %v", err)
	}
	toolsResp, err := json.Marshal(rpcResponse{
		JSONRPC: "2.0",
		ID:      2,
		Result:  json.RawMessage(`{"tools":[{"name":"read_file","description":"Reads a file."}]}`),
	})
	if err != nil {
		t.Fatalf("marshal toolsResp: %v", err)
	}
	return []string{string(initResp), string(toolsResp)}
}

// TestProbe_RealPath_AppliedFalseDemotesTier is the headline regression test
// for SBX-1. It drives the PRODUCTION newStdioClient/probeOne path (NO
// setStdioClientSeam) with a real sandbox.Session that reports
// Tier()=="landlock" but Applied()==false. The honest-demotion block in
// probe.go must override the "landlock" label and report SandboxTier=="tier0"
// and SandboxApplied==false. Deleting that block in probe.go makes this test
// fail (see report) — proving it locks the production behavior, not a fake's.
func TestProbe_RealPath_AppliedFalseDemotesTier(t *testing.T) {
	r := &tierRunner{
		responses: minimalHandshakeResponses(t),
		tier:      "landlock",
		applied:   false,
	}
	specs := []ServerSpec{{
		Client: "openclaw", Name: "filesystem", Transport: "stdio", Command: "npx",
	}}
	path := filepath.Join(t.TempDir(), "mcp-baseline.json")

	probe := Probe(specs, r, path, time.Now().UTC())
	if probe == nil || len(probe.Servers) != 1 {
		t.Fatalf("want 1 server probe, got %+v", probe)
	}
	sp := probe.Servers[0]
	// The handshake must have succeeded so we know the session's stdout was
	// genuinely driven through the production StdioTransport, not short-circuited.
	if !sp.Reached {
		t.Fatalf("server not Reached; errors=%v — handshake did not run through the real transport", sp.Errors)
	}
	if sp.SandboxApplied {
		t.Errorf("SandboxApplied = true, want false when session.Applied()==false")
	}
	if sp.SandboxTier != "tier0" {
		t.Errorf("SandboxTier = %q, want \"tier0\": production must DEMOTE a "+
			"\"landlock\" label to tier0 when confinement did not actually engage", sp.SandboxTier)
	}
}

// TestProbe_RealPath_AppliedTrueKeepsTier is the companion case: a real session
// reporting Tier()=="landlock" AND Applied()==true must keep the "landlock"
// label and report SandboxApplied==true. Together with the demotion case above,
// this pins the exact conditional in probe.go: demote iff !applied.
func TestProbe_RealPath_AppliedTrueKeepsTier(t *testing.T) {
	r := &tierRunner{
		responses: minimalHandshakeResponses(t),
		tier:      "landlock",
		applied:   true,
	}
	specs := []ServerSpec{{
		Client: "openclaw", Name: "filesystem", Transport: "stdio", Command: "npx",
	}}
	path := filepath.Join(t.TempDir(), "mcp-baseline.json")

	probe := Probe(specs, r, path, time.Now().UTC())
	if probe == nil || len(probe.Servers) != 1 {
		t.Fatalf("want 1 server probe, got %+v", probe)
	}
	sp := probe.Servers[0]
	if !sp.Reached {
		t.Fatalf("server not Reached; errors=%v", sp.Errors)
	}
	if !sp.SandboxApplied {
		t.Errorf("SandboxApplied = false, want true when session.Applied()==true")
	}
	if sp.SandboxTier != "landlock" {
		t.Errorf("SandboxTier = %q, want \"landlock\": a genuinely-applied tier "+
			"must NOT be demoted", sp.SandboxTier)
	}
}
