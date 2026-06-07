package model

import "time"

// SignalsVersion is the schema version of the Signals document emitted by
// 'keelix collect' and consumed by Load.
const SignalsVersion = "1.0.0"

// Signals is the inside-out fact set gathered on the host by internal/collect.
// Like ProbeResult it is PURE DATA: it performs no I/O and is fully
// serializable. The only producer is collect.Collect (the I/O boundary).
type Signals struct {
	Version     string            `json:"version"`
	CollectedAt time.Time         `json:"collected_at"`
	Platform    Platform          `json:"platform"`
	Privilege   Privilege         `json:"privilege"`
	Sockets     []ListeningSocket `json:"sockets,omitempty"`
	Files       []FileFact        `json:"files,omitempty"`
	Configs     []ConfigFact      `json:"configs,omitempty"`
	Processes   []ProcessFact     `json:"processes,omitempty"`
	Packages    PackageState      `json:"packages"`
	Firewall    FirewallState     `json:"firewall"`
	Errors      []CollectError    `json:"errors,omitempty"`
	MCPProbe    *MCPProbe         `json:"mcp_probe,omitempty"`
}

// Platform describes the host OS. OS is "linux" or "darwin".
type Platform struct {
	OS      string `json:"os"`
	Distro  string `json:"distro,omitempty"`
	Version string `json:"version,omitempty"`
	IsVM    bool   `json:"is_vm,omitempty"`
}

// Privilege describes the effective privilege of the collector process.
type Privilege struct {
	Root bool `json:"root"`
	EUID int  `json:"euid"`
}

// ListeningSocket is one observed listening socket. Bind is the literal bind
// address, e.g. "127.0.0.1", "0.0.0.0", "::", "100.x" (overlay), "10.x" (LAN).
type ListeningSocket struct {
	Proto string `json:"proto"`
	Bind  string `json:"bind"`
	Port  int    `json:"port"`
	PID   int    `json:"pid,omitempty"`
	UID   int    `json:"uid,omitempty"`
	Comm  string `json:"comm,omitempty"`
}

// FileFact is the observed state of a single allowlisted path. Mode is an
// octal string, e.g. "0600".
type FileFact struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`
	UID    int    `json:"uid,omitempty"`
	GID    int    `json:"gid,omitempty"`
	Size   int64  `json:"size,omitempty"`
}

// ConfigFact is a parsed configuration file. Values holds flattened key/value
// pairs; SchemaKnown is true when the parser recognized the schema.
type ConfigFact struct {
	Source      string            `json:"source"`
	Mode        string            `json:"mode,omitempty"`
	SchemaID    string            `json:"schema_id,omitempty"`
	SchemaKnown bool              `json:"schema_known"`
	Values      map[string]string `json:"values,omitempty"`
}

// ProcessFact is an observed process of interest.
type ProcessFact struct {
	Comm   string     `json:"comm"`
	PID    int        `json:"pid"`
	UID    int        `json:"uid"`
	Args   []string   `json:"args,omitempty"`
	Groups []string   `json:"groups,omitempty"`
	Env    []EnvShape `json:"env,omitempty"`
}

// EnvShape is the shape (not the value) of an environment variable. Class is
// one of "empty", "secret", "path", "plain".
type EnvShape struct {
	Name  string `json:"name"`
	Class string `json:"class"`
}

// PackageState summarizes the host package manager security posture.
type PackageState struct {
	Manager                string `json:"manager,omitempty"`
	SecurityUpdatesPending int    `json:"security_updates_pending,omitempty"`
	RebootRequired         bool   `json:"reboot_required,omitempty"`
	DistroEOL              bool   `json:"distro_eol,omitempty"`
}

// FirewallState summarizes the host firewall. Backend is one of "ufw",
// "nftables", "firewalld", "pf", "none".
type FirewallState struct {
	Backend        string   `json:"backend,omitempty"`
	DefaultInbound string   `json:"default_inbound,omitempty"`
	Rules          []string `json:"rules,omitempty"`
}

// CollectError records a non-fatal per-domain collection failure.
type CollectError struct {
	Domain string `json:"domain"`
	Err    string `json:"err"`
}

// MCPProbe holds the results of an active MCP server probe (populated by SP1b;
// nil in SP1a static-analysis mode). Its presence on Signals allows MCP007 and
// future active-probe checks to compile and return StatusNotAssessed cleanly.
type MCPProbe struct {
	Servers []MCPServerProbe `json:"servers,omitempty"`
	// CorruptBaseline is set when the on-disk baseline file exists but contains
	// invalid JSON (a partial/corrupt write). MCP007 emits a Critical finding
	// when this is true because drift detection is impaired: all tools appear as
	// FirstSeen rather than being compared against the stored hashes. SBX-9(b).
	CorruptBaseline bool `json:"corrupt_baseline,omitempty"`
}

// MCPServerProbe is the observed state of one MCP server reached during an
// active probe. Transport is one of "stdio", "http", "sse".
// SandboxApplied is true only when the sandbox runner verified that real
// kernel confinement (Landlock / Seatbelt) took effect; false means the probe
// ran under Tier-0 process hygiene only (clean env, tempdir, pgid kill).
type MCPServerProbe struct {
	Client         string        `json:"client"`
	Name           string        `json:"name"`
	Transport      string        `json:"transport"`
	Reached        bool          `json:"reached"`
	SandboxTier    string        `json:"sandbox_tier,omitempty"`
	SandboxApplied bool          `json:"sandbox_applied,omitempty"`
	Tools          []MCPToolFact `json:"tools,omitempty"`
	Errors         []string      `json:"errors,omitempty"`
}

// MCPToolFact describes one tool advertised by an MCP server during an active
// probe. DescHash is the SHA-256 of the tool description (for drift detection).
type MCPToolFact struct {
	Name      string `json:"name"`
	DescHash  string `json:"desc_hash,omitempty"`
	Drifted   bool   `json:"drifted,omitempty"`
	FirstSeen bool   `json:"first_seen,omitempty"`
}

// SocketByPort returns the first listening socket matching the given port.
// ok is false when no socket matches.
func (s *Signals) SocketByPort(port int) (ListeningSocket, bool) {
	if s == nil {
		return ListeningSocket{}, false
	}
	for _, sock := range s.Sockets {
		if sock.Port == port {
			return sock, true
		}
	}
	return ListeningSocket{}, false
}
