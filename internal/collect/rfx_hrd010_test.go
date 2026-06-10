package collect

// TestRFX_HRD010_ParserFed is the MANDATORY PARSER-FED pipeline integration
// test for HRD010 (non-root docker-group membership).
//
// Before FIX-2, ps output contains no "groups" column, so ProcessFact.Groups
// was always nil and HRD010's inner loop was dead — it could never fire.
//
// This test locks the repair: it calls the real parseProcesses parser over a
// committed ps fixture, then calls populateProcessGroupsFromFiles (the new
// Linux helper) over committed /etc/passwd + /etc/group fixtures, and asserts:
//
//  1. alice (UID 1000), who is in the docker group per /etc/group, has
//     ProcessFact.Groups containing "docker".
//  2. HRD010.Run() fires (FAIL) for that fact.
//  3. bob (UID 1001), who is NOT in the docker group, gets Groups that do NOT
//     include "docker", and HRD010 returns Pass.
//
// Fixtures: testdata/etc_passwd_docker.txt + testdata/etc_group_docker.txt
// (committed; no temp-file writes needed).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/hardening"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX_HRD010_ParserFed_DockerGroupFires(t *testing.T) {
	passwdPath := filepath.Join("testdata", "etc_passwd_docker.txt")
	groupPath := filepath.Join("testdata", "etc_group_docker.txt")

	passwdBytes, err := os.ReadFile(passwdPath)
	if err != nil {
		t.Fatalf("read passwd fixture: %v", err)
	}
	groupBytes, err := os.ReadFile(groupPath)
	if err != nil {
		t.Fatalf("read group fixture: %v", err)
	}

	// Build a ps-style process list where alice (uid 1000) runs a process.
	// We construct the bytes directly so parseProcesses (the real parser) runs.
	psOutput := []byte("  PID   UID COMMAND         COMMAND\n" +
		" 1337  1000 node            node /app/server.js\n" +
		" 1338  1001 bash            bash\n")

	procs := parseProcesses(psOutput)
	if len(procs) != 2 {
		t.Fatalf("parseProcesses: want 2 processes, got %d: %+v", len(procs), procs)
	}

	// --- STEP: populate Groups from /etc/passwd + /etc/group ---
	// Before FIX-2 this function does not exist; test will fail to compile,
	// confirming the bug. After FIX-2 it is implemented in processes_linux.go
	// (Linux build tag) or a shared helper file.
	populateProcessGroupsFromFiles(procs, passwdBytes, groupBytes)

	// alice (uid 1000) should be in the docker group.
	aliceProc := procs[0]
	if aliceProc.UID != 1000 {
		t.Fatalf("expected uid 1000 for first proc, got %d", aliceProc.UID)
	}
	hasDocker := false
	for _, g := range aliceProc.Groups {
		if strings.ToLower(g) == "docker" {
			hasDocker = true
		}
	}
	if !hasDocker {
		t.Errorf("alice (uid 1000) Groups=%v — missing 'docker'; populateProcessGroupsFromFiles did not populate from /etc/group",
			aliceProc.Groups)
	}

	// bob (uid 1001) should NOT be in docker group.
	bobProc := procs[1]
	if bobProc.UID != 1001 {
		t.Fatalf("expected uid 1001 for second proc, got %d", bobProc.UID)
	}
	for _, g := range bobProc.Groups {
		if strings.ToLower(g) == "docker" {
			t.Errorf("bob (uid 1001) Groups=%v — should NOT contain 'docker'", bobProc.Groups)
		}
	}

	// --- STEP: run HRD010 with alice's process (docker group member) — must FIRE ---
	c := findRegisteredCheck(t, "HRD010")

	aliceCtx := &model.ScanContext{
		Collector: &model.Signals{
			Platform:  model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{aliceProc},
		},
	}
	aliceFindings := c.Run(aliceCtx)
	fired := false
	for _, f := range aliceFindings {
		if !f.Passed && f.CheckID == "HRD010" {
			fired = true
		}
	}
	if !fired {
		t.Errorf("HRD010 did NOT fire for alice (uid 1000) in docker group; Groups=%v findings=%+v",
			aliceProc.Groups, aliceFindings)
	}

	// --- STEP: run HRD010 with bob's process (no docker group) — must PASS ---
	bobCtx := &model.ScanContext{
		Collector: &model.Signals{
			Platform:  model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{bobProc},
		},
	}
	bobFindings := c.Run(bobCtx)
	for _, f := range bobFindings {
		if !f.Passed && f.CheckID == "HRD010" {
			t.Errorf("HRD010 fired for bob (uid 1001) who is NOT in docker group; Groups=%v findings=%+v",
				bobProc.Groups, bobFindings)
		}
	}
}
