package mcpprobe

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// baselineEntry is one persisted tool fingerprint keyed by "client|server|tool".
type baselineEntry struct {
	Hash        string    `json:"hash"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	PendingHash string    `json:"pending_hash,omitempty"` // observed-but-unapproved hash on drift; never replaces Hash until explicit re-baseline
	// ServerCommand and ServerURL record the server identity at baseline time.
	// A change in either field means the operator re-pointed the server; this is
	// NOT a rug-pull. We treat it as FirstSeen (re-inventory under the new identity)
	// rather than Drifted, because the attacker-controlled signal is the tool
	// description, not the server binary/URL which the operator controls.
	ServerCommand string `json:"server_command,omitempty"`
	ServerURL     string `json:"server_url,omitempty"`
}

// Baseline is the on-disk fingerprint store at ~/.keelix/mcp-baseline.json.
// All mutating operations take an injected `now` — there is no time.Now() here.
type Baseline struct {
	entries map[string]baselineEntry
}

// DiffResult reports what Diff observed for one tool.
type DiffResult struct {
	FirstSeen bool
	Drifted   bool
	Hash      string
}

func newBaseline() *Baseline { return &Baseline{entries: map[string]baselineEntry{}} }

func keyOf(client, server, tool string) string {
	return client + "|" + server + "|" + tool
}

// LoadBaseline reads the baseline JSON at path. A missing file yields an empty
// baseline (not an error) — that is the first-run case.
func LoadBaseline(path string) (*Baseline, error) {
	bl := newBaseline()
	b, err := os.ReadFile(path) // #nosec G304 -- path is the user's own keelix baseline file under their home dir
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return bl, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return bl, nil
	}
	if err := json.Unmarshal(b, &bl.entries); err != nil {
		// A corrupt baseline must return an error so the caller can emit a finding
		// rather than silently resetting to first-run (which would erase all
		// accumulated drift detection). SBX-9(b).
		return nil, fmt.Errorf("mcp-baseline: corrupt JSON at %s: %w", path, err)
	}
	if bl.entries == nil {
		bl.entries = map[string]baselineEntry{}
	}
	return bl, nil
}

// Save writes the baseline to path (0600), creating the parent dir if needed.
// The write is ATOMIC: data is written to a temp file in the same directory and
// then renamed over the target, so a concurrent reader can never observe a
// partial write. SBX-9(b).
func (b *Baseline) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Marshal deterministically by sorting keys via an ordered intermediate.
	keys := make([]string, 0, len(b.entries))
	for k := range b.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]baselineEntry, len(b.entries))
	for _, k := range keys {
		ordered[k] = b.entries[k]
	}
	data, err := json.MarshalIndent(ordered, "", "  ")
	if err != nil {
		return err
	}
	// Write to a sibling temp file then atomically rename over the target so no
	// reader ever sees a partial JSON blob. The temp file is created in the same
	// directory as the target to guarantee rename stays on the same filesystem.
	tmp, err := os.CreateTemp(dir, ".mcp-baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("mcp-baseline: create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: remove the temp file if we return an error.
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp-baseline: write temp: %w", err)
	}
	if err = tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("mcp-baseline: chmod temp: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("mcp-baseline: close temp: %w", err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("mcp-baseline: rename: %w", err)
	}
	return nil
}

// ServerIdentity carries the operator-controlled server identity for a Diff call.
// Command is the stdio command string; URL is the remote server URL.
// Exactly one should be non-empty for a given server spec.
type ServerIdentity struct {
	Command string
	URL     string
}

// Diff records the observed hash for client|server|tool at time now and reports
// whether it is the first observation (FirstSeen) or a changed hash for a
// previously-seen tool (Drifted). A first run is inventory only: FirstSeen with
// Drifted=false.
//
// SBX-6 invariant: on a Drifted observation the stored Hash is NEVER overwritten
// with the new (potentially poisoned) hash. The unapproved hash is recorded in
// PendingHash for reporting only. Hash is updated solely for FirstSeen (inventory)
// or via an explicit re-baseline approval path. This ensures a poisoned server
// keeps failing MCP007 on every subsequent scan until a human explicitly approves
// the change.
//
// SBX-8(b) invariant: Drifted is only set when the description hash changed AND
// the server identity (Command/URL) is UNCHANGED. If the server identity changed,
// the operator re-pointed the server (a benign operation); the entry is reset as
// FirstSeen under the new identity. This prevents false-positive Critical findings
// when an operator legitimately switches MCP server implementations.
func (b *Baseline) Diff(client, server, tool, hash string, now time.Time, id ServerIdentity) DiffResult {
	k := keyOf(client, server, tool)
	prev, seen := b.entries[k]
	if !seen {
		b.entries[k] = baselineEntry{
			Hash:          hash,
			FirstSeen:     now,
			LastSeen:      now,
			ServerCommand: id.Command,
			ServerURL:     id.URL,
		}
		return DiffResult{FirstSeen: true, Hash: hash}
	}
	// SBX-8(b): if the server identity changed, treat as FirstSeen (re-inventory).
	// The operator controls the command/URL; a change there is a re-point, not a
	// rug-pull. Reset the entry under the new identity.
	if prev.ServerCommand != id.Command || prev.ServerURL != id.URL {
		b.entries[k] = baselineEntry{
			Hash:          hash,
			FirstSeen:     now,
			LastSeen:      now,
			ServerCommand: id.Command,
			ServerURL:     id.URL,
		}
		return DiffResult{FirstSeen: true, Hash: hash}
	}
	drifted := prev.Hash != hash
	if drifted {
		// Keep the original approved hash; record the observed (unapproved) hash
		// as PendingHash so it surfaces in reports without silently accepting it.
		prev.PendingHash = hash
	} else {
		// Hash is unchanged — clear any stale pending observation and advance LastSeen.
		prev.PendingHash = ""
		prev.LastSeen = now
	}
	b.entries[k] = prev
	return DiffResult{Drifted: drifted, Hash: hash}
}
