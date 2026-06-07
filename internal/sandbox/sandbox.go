// Package sandbox is the I/O boundary that spawns MCP server processes under a
// best-effort isolation tier. It is the ONLY package in SP1b that executes
// untrusted code, so it is off by default (the caller gates execution behind
// consent) and every spawn drops the parent environment, runs in a throwaway
// tempdir, and confines the child to its own process group for reliable kill.
//
// Three tiers exist. Tier-0 (baseRunner, in this file) applies the
// process-level hygiene that needs no special kernel support and is the
// fallback on unsupported platforms. The linux runner adds Landlock + rlimits;
// the darwin runner adds a Seatbelt profile. NewRunner is build-tagged to
// select the strongest tier the host can offer.
//
// Available() (build-tagged per platform) reports whether a real kernel-level
// sandbox tier is usable on the current host, allowing callers such as the
// engine to gate execution of untrusted code behind a real confinement check.
package sandbox

import (
	"context"
	"io"
	"time"
)

// defaultOutputCap bounds stdout+stderr capture when Spec.OutputCap is zero.
const defaultOutputCap int64 = 1 << 20 // 1 MiB

// Spec describes one child process to run under the sandbox. Env is the
// COMPLETE environment the child will see for variables the caller chooses to
// pass; the runner never inherits os.Environ(). Timeout is a hard ceiling
// after which the whole process group is killed.
type Spec struct {
	Command   string
	Args      []string
	Env       map[string]string
	Timeout   time.Duration
	OutputCap int64 // max bytes captured per stream; <=0 means defaultOutputCap
}

// Result is the outcome of a completed (non-streaming) Run.
type Result struct {
	Stdout         []byte
	Stderr         []byte
	ExitCode       int
	TimedOut       bool
	Tier           string // "tier0" | "landlock" | "bwrap" | "seatbelt"
	SandboxApplied bool   // true only when real kernel confinement took effect
	Notes          []string
}

// Runner spawns sandboxed children. Run executes to completion and returns a
// Result; Start returns a streaming Session for stdio JSON-RPC (used by the
// MCP probe in SLD).
type Runner interface {
	Run(ctx context.Context, s Spec) (*Result, error)
	Start(ctx context.Context, s Spec) (Session, error)
}

// Session is a live sandboxed child whose stdin/stdout the caller drives. The
// sandbox tier that produced it is exposed via Tier so the probe can record
// it. Applied reports whether real kernel confinement (Landlock/Seatbelt) was
// verified to have taken effect; false means Tier-0 process hygiene only.
// Close terminates the child's process group and releases the tempdir.
type Session interface {
	Stdin() io.Writer
	Stdout() io.Reader
	Tier() string
	Applied() bool
	Close() error
}
