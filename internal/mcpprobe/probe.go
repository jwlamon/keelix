package mcpprobe

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/sandbox"
)

// defaultProbeTimeout bounds each server's whole handshake+list wall clock.
const defaultProbeTimeout = 20 * time.Second

// ServerSpec is a derived intent to probe one MCP server. For stdio the probe
// spawns Command+Args through the sandbox Runner with only EnvKeys' values
// passed through (the engine resolves EnvKeys to values before calling Probe,
// or leaves them as keys the sandbox baseline blanks — see engine wiring).
// For http it POSTs to URL.
type ServerSpec struct {
	Client    string
	Name      string
	Transport string // "stdio" | "http"
	Command   string
	Args      []string
	EnvKeys   []string
	URL       string
}

// newStdioClient builds an MCPClient over a sandboxed stdio Session for the
// given spec. It is a package var so tests can substitute a direct in-process
// transport (avoiding a real child) without touching Probe's logic.
// Returns (client, tier, applied, closer, error). applied reflects Session.Applied():
// true only when real kernel confinement engaged; false means Tier-0 only.
var newStdioClient = func(ctx context.Context, r sandbox.Runner, spec ServerSpec) (*MCPClient, string, bool, func() error, error) {
	env := map[string]string{}
	// EnvKeys entries are resolved here: if the entry contains "=" it is a
	// literal "KEY=VALUE" pair (integer-indexed Docker-style env from the config)
	// and is injected directly; otherwise the entry is a named env var whose
	// value is looked up from the host process via os.Getenv. The sandbox never
	// inherits os.Environ(), so only entries resolved here reach the child.
	for _, entry := range spec.EnvKeys {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			env[entry[:idx]] = entry[idx+1:]
		} else if v := os.Getenv(entry); v != "" {
			env[entry] = v
		}
	}
	spec0 := sandbox.Spec{
		Command:   spec.Command,
		Args:      spec.Args,
		Env:       env,
		Timeout:   defaultProbeTimeout,
		OutputCap: 1 << 20,
	}
	sess, err := r.Start(ctx, spec0)
	if err != nil {
		return nil, "", false, nil, err
	}
	tier := "tier0"
	applied := sess.Applied()
	if tv := sess.Tier(); tv != "" {
		tier = tv
	}
	// Honest tier demotion: if the session reports Applied()==false, the probe
	// ran under Tier-0 process hygiene only regardless of what tier label the
	// runner selected (e.g. a kernel without Landlock support silently degrades).
	if !applied {
		tier = "tier0"
	}
	tr := NewStdioTransport(sess)
	return newClient(tr), tier, applied, tr.Close, nil
}

// Probe runs the active MCP probe across specs, isolating each stdio server in
// the sandbox Runner and POSTing to each http server. It diffs every tool
// against the baseline at baselinePath using the injected now, then persists
// the updated baseline. One server's failure NEVER fails the whole probe — it
// is recorded as Reached=false with an Errors entry.
//
// If the on-disk baseline is corrupt (valid path, invalid JSON), Probe sets
// MCPProbe.CorruptBaseline=true so MCP007 can emit a Critical finding. Drift
// detection is impaired in this case (all tools appear as FirstSeen). SBX-9(b).
func Probe(specs []ServerSpec, r sandbox.Runner, baselinePath string, now time.Time) *model.MCPProbe {
	bl, err := LoadBaseline(baselinePath)
	out := &model.MCPProbe{}
	if err != nil {
		bl = newBaseline()
		out.CorruptBaseline = true
	}
	for _, spec := range specs {
		out.Servers = append(out.Servers, probeOne(spec, r, bl, now))
	}
	// Best-effort persist; a save failure must not invalidate the in-memory
	// results we already computed.
	_ = bl.Save(baselinePath)
	return out
}

func probeOne(spec ServerSpec, r sandbox.Runner, bl *Baseline, now time.Time) model.MCPServerProbe {
	sp := model.MCPServerProbe{
		Client:    spec.Client,
		Name:      spec.Name,
		Transport: spec.Transport,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultProbeTimeout)
	defer cancel()

	var client *MCPClient
	var tier string
	var sandboxApplied bool
	var closer func() error

	switch spec.Transport {
	case "http", "sse":
		// SSE and streamable-HTTP servers both accept JSON-RPC via HTTP POST.
		// We do not open an SSE stream — a single POST per call suffices for
		// tool discovery (initialize + tools/list). Route both types through
		// the HTTPTransport so we never attempt to spawn an SSE server as a
		// stdio child process.
		if spec.URL == "" {
			sp.Errors = append(sp.Errors, spec.Transport+" transport with empty url")
			return sp
		}
		client = newClient(NewHTTPTransport(spec.URL, defaultProbeTimeout))
		tier = spec.Transport
		sandboxApplied = false // no sandbox for HTTP/SSE transport
		closer = func() error { return nil }
	default: // stdio
		c, tr, appl, cl, err := newStdioClient(ctx, r, spec)
		if err != nil {
			sp.Errors = append(sp.Errors, "spawn: "+err.Error())
			return sp
		}
		client, tier, sandboxApplied, closer = c, tr, appl, cl
	}
	defer func() { _ = closer() }()

	sp.SandboxTier = tier
	sp.SandboxApplied = sandboxApplied

	tools, err := client.discover()
	if err != nil {
		sp.Errors = append(sp.Errors, err.Error())
		return sp
	}
	sp.Reached = true

	// Build the server identity for SBX-8(b): a re-point of the server binary
	// or URL is operator-controlled and must not trigger drift.
	srvID := ServerIdentity{Command: spec.Command, URL: spec.URL}
	for _, tl := range tools {
		h := canonicalHash(tl.Name, tl.Description)
		d := bl.Diff(spec.Client, spec.Name, tl.Name, h, now, srvID)
		sp.Tools = append(sp.Tools, model.MCPToolFact{
			Name:      tl.Name,
			DescHash:  h,
			Drifted:   d.Drifted,
			FirstSeen: d.FirstSeen,
		})
	}
	return sp
}
