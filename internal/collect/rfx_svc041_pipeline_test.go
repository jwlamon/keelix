package collect

// TestSVC041_Pipeline_KindTableAndDirectCollect is the MANDATORY PARSER-FED
// pipeline integration test for FIX-1 (SP3 remediation).
//
// It guards against the two bugs fixed by FIX-1:
//
//  1. "nfs-exports" was absent from kindTable → ServiceConfigCandidates never
//     returned a candidate for NFS containers → SVC041 was permanently
//     NotAssessed in production.
//
//  2. /etc/exports was never directly collected → host NFS daemons (not
//     containerised) were also never assessed.
//
// The test routes the fixture through collectServiceConfigs (which calls
// collectConfig → parse → redact) so the full pipeline is exercised, NOT a
// hand-built model.ConfigFact.

import (
	"os"
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

// TestSVC041_Pipeline_KindTable verifies that a model.Stack with an nfs-server
// image bind-mounting the committed exports fixture flows through
// ServiceConfigCandidates → collectServiceConfigs → SVC041 and fires.
//
// This test FAILS before the FIX-1 kindTable addition because
// ServiceConfigCandidates returns no candidates for nfs-server images.
func TestSVC041_Pipeline_KindTable(t *testing.T) {
	c := findRegisteredCheck(t, "SVC041")

	// Copy the fixture to a temp file named "exports" so the basename matches
	// the kindTable expectedBasenames entry. (The committed fixture is named
	// "nfs_norootsquash.exports" for readability; production bind-mounts use
	// "exports" as the basename because the source is /etc/exports.)
	fixtureContent, err := os.ReadFile(filepath.Join("testdata", "nfs_norootsquash.exports"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	tmpDir := t.TempDir()
	exportsPath := filepath.Join(tmpDir, "exports")
	if err := os.WriteFile(exportsPath, fixtureContent, 0o644); err != nil {
		t.Fatalf("write temp exports: %v", err)
	}

	// Build a model.Stack with an nfs-server service that bind-mounts the
	// temp exports file at /etc/exports inside the container.
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "nfs",
				Image: "itsthenetwork/nfs-server-alpine:latest",
				Volumes: []model.VolumeMount{
					{
						Type:   "bind",
						Source: exportsPath,
						Target: "/etc/exports",
					},
				},
			},
		},
	}

	// Step 1: ServiceConfigCandidates must discover the nfs-exports candidate.
	candidates := ServiceConfigCandidates(stack)
	var nfsCand *ConfigCandidate
	for i := range candidates {
		if candidates[i].SchemaID == "nfs-exports" {
			nfsCand = &candidates[i]
			break
		}
	}
	if nfsCand == nil {
		t.Fatalf("ServiceConfigCandidates returned no nfs-exports candidate — "+
			"nfs-exports is missing from kindTable (FIX-1 kindTable gap).\n"+
			"Candidates returned: %+v", candidates)
	}

	// Step 2: collectServiceConfigs must produce a SchemaKnown fact.
	opts := Options{
		ServiceConfigs: candidates,
	}
	facts := collectServiceConfigs(opts)
	var nfsFact *model.ConfigFact
	for i := range facts {
		if facts[i].SchemaID == "nfs-exports" {
			nfsFact = &facts[i]
			break
		}
	}
	if nfsFact == nil {
		t.Fatalf("collectServiceConfigs returned no nfs-exports fact; all facts: %+v", facts)
	}
	if !nfsFact.SchemaKnown {
		t.Fatalf("collectServiceConfigs: SchemaKnown=false for nfs-exports; Values=%v", nfsFact.Values)
	}

	// Step 3: SVC041 must fire with the pipeline-produced fact (not a hand-built one).
	ctx := &model.ScanContext{
		Collector: &model.Signals{Configs: []model.ConfigFact{*nfsFact}},
	}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC041" && f.IsFail() {
			return // correct
		}
	}
	t.Fatalf("SVC041: want failing finding for no_root_squash=true via pipeline; got %+v\nValues: %v",
		findings, nfsFact.Values)
}

// TestSVC041_Pipeline_DirectHostFile verifies that the direct /etc/exports
// host-file read path (added by FIX-1) produces a SchemaKnown nfs-exports fact
// when the file is present.
//
// Because /etc/exports is a host-system path we write a temp file, add it to
// the allowlist for the duration of the test (matching the production pattern
// used for dockerDaemonFact in collect.go), and confirm collectConfig returns
// a SchemaKnown fact.
func TestSVC041_Pipeline_DirectHostFile(t *testing.T) {
	// Copy the fixture content to a temp file that we'll treat as /etc/exports.
	fixtureContent, err := os.ReadFile(filepath.Join("testdata", "nfs_norootsquash.exports"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	tmpDir := t.TempDir()
	tmpExports := filepath.Join(tmpDir, "exports")
	if err := os.WriteFile(tmpExports, fixtureContent, 0o644); err != nil {
		t.Fatalf("write temp exports: %v", err)
	}

	// Temporarily add the temp path to the allowlist (matching how
	// collectServiceConfigs grants one-off entries).
	allowlist = append(allowlist, allowEntry{Path: tmpExports})
	t.Cleanup(func() {
		allowlist = allowlist[:len(allowlist)-1]
	})

	fact := collectConfig(tmpExports, parseNFSExports)
	if !fact.SchemaKnown {
		t.Fatalf("collectConfig: SchemaKnown=false for temp exports file; Values=%v", fact.Values)
	}
	if fact.SchemaID != "nfs-exports" {
		t.Fatalf("collectConfig: SchemaID=%q, want nfs-exports", fact.SchemaID)
	}
	// The fixture has no_root_squash; confirm the key survives redaction.
	if fact.Values["no_root_squash"] != "true" {
		t.Fatalf("collectConfig: no_root_squash=%q after redaction, want true; all values: %v",
			fact.Values["no_root_squash"], fact.Values)
	}
}

// TestSVC041_ParserFed_Pipeline_CollectConfigInternal upgrades the existing
// SVC041 parser-fed test to route through collectConfigInternal (parse+redact)
// instead of calling parseNFSExports directly.  This guards against any future
// redaction interaction that could silently break the check.
func TestSVC041_ParserFed_Pipeline_CollectConfigInternal(t *testing.T) {
	c := findRegisteredCheck(t, "SVC041")

	fact := collectConfigInternal(
		filepath.Join("testdata", "nfs_norootsquash.exports"),
		parseNFSExports,
	)
	if !fact.SchemaKnown {
		t.Fatalf("collectConfigInternal: SchemaKnown=false; Values=%v", fact.Values)
	}
	if fact.SchemaID != "nfs-exports" {
		t.Fatalf("collectConfigInternal: SchemaID=%q, want nfs-exports", fact.SchemaID)
	}

	ctx := &model.ScanContext{
		Collector: &model.Signals{Configs: []model.ConfigFact{fact}},
	}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC041" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC041: want failing finding for no_root_squash=true via collectConfigInternal; "+
		"got %+v\nValues: %v", findings, fact.Values)
}
