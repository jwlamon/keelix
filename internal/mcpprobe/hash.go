// Package mcpprobe is the consent-gated, sandboxed active MCP probe (SP1b):
// a hand-rolled JSON-RPC 2.0 client that spawns each configured stdio MCP
// server through internal/sandbox (or connects to an HTTP one), runs
// initialize -> tools/list, hashes each tool's name+description, and diffs
// against a stored baseline to surface tool-poisoning / rug-pull drift.
//
// Everything except the transports and baseline file I/O is pure: timestamps
// are injected (no time.Now() inside this package), so drift detection is
// deterministic and testable.
package mcpprobe

import (
	"crypto/sha256"
	"encoding/hex"
)

// canonicalHash returns the lowercase hex SHA-256 of the canonical form
// "name\ndescription". The '\n' delimiter prevents name/description boundary
// collisions. A change in either field changes the hash — that is the drift
// signal MCP007 keys off of.
func canonicalHash(name, description string) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n'})
	h.Write([]byte(description))
	return hex.EncodeToString(h.Sum(nil))
}
