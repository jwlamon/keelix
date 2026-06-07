package mcp

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

// run006 is a test helper that calls the mcp006 check's Run method.
func run006(ctx *model.ScanContext) []model.Finding {
	return (&mcp006{}).Run(ctx)
}

func TestIsVerifiedProvenance(t *testing.T) {
	verified := []string{
		"@modelcontextprotocol/server-filesystem",
		"@anthropic-ai/sdk",
		// NOTE: @github/, @google/, @microsoft/, @azure/, @aws/, @cloudflare/ are
		// megascopes removed in SF-4 (c). Only MCP-exclusive publishers remain.
		"mcp-server-git", // official registry publisher (bare name)
		"ghcr.io/modelcontextprotocol/server-git@sha256:" +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"docker.io/mcp/server-fetch:1.2@sha256:" +
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	for _, a := range verified {
		if !isVerifiedProvenance(a) {
			t.Errorf("isVerifiedProvenance(%q) = false, want true", a)
		}
	}

	unverified := []string{
		"@randomuser/some-mcp",                    // unknown scope
		"github:randomuser/repo",                  // individual repo
		"some-unknown-package",                    // bare, not a registry publisher
		"ghcr.io/modelcontextprotocol/server-git", // trusted base but NO digest pin
		"docker.io/evil/server@sha256:" + // digest but untrusted base
			"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		// SF-4 (c): megascopes that were erroneously in verifiedNPMScopes
		"@github/mcp-server",
		"@google/some-mcp",
		"@microsoft/mcp",
		"@azure/mcp",
		"@aws/mcp",
		"@cloudflare/mcp",
	}
	for _, a := range unverified {
		if isVerifiedProvenance(a) {
			t.Errorf("isVerifiedProvenance(%q) = true, want false", a)
		}
	}
}

// TestBarePackageName covers SF-4 (b): jsr:/npm: scheme stripping.
func TestBarePackageName(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Plain npm scoped package (unchanged)
		{"@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-filesystem"},
		// Version-pinned npm package
		{"mcp-server-git==1.2.3", "mcp-server-git"},
		{"mcp-server-git@1.2.3", "mcp-server-git"},
		// jsr: scheme must be stripped before splitting — SF-4 (b)
		{"jsr:@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-filesystem"},
		{"jsr:@scope/pkg@1.0.0", "@scope/pkg"},
		// npm: scheme must be stripped — SF-4 (b)
		{"npm:@anthropic/mcp-server@2.0.0", "@anthropic/mcp-server"},
		{"npm:mcp-server-git==1.2.3", "mcp-server-git"},
		// npx: scheme
		{"npx:@modelcontextprotocol/server-git", "@modelcontextprotocol/server-git"},
	}
	for _, tc := range cases {
		got := barePackageName(tc.input)
		if got != tc.want {
			t.Errorf("barePackageName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestStripRegistryScheme covers SF-4 (b): scheme-stripping for isVerifiedProvenance.
func TestIsVerifiedProvenance_JSR(t *testing.T) {
	// jsr:@modelcontextprotocol/server-filesystem — after scheme strip → verified scope
	if !isVerifiedProvenance("jsr:@modelcontextprotocol/server-filesystem") {
		t.Error("jsr:@modelcontextprotocol/server-filesystem should be verified (after scheme strip)")
	}
	// jsr:@randomuser/some-mcp — after scheme strip → still unverified
	if isVerifiedProvenance("jsr:@randomuser/some-mcp") {
		t.Error("jsr:@randomuser/some-mcp should NOT be verified")
	}
}

// TestSR3_ContainerValueCarryingFlags covers SR-3: value-carrying flags whose
// value arg must be skipped before identifying the image reference.
// Before the fix, `-e FOO=BAR` would cause `FOO=BAR` to be treated as the image
// reference, flagging it as unverified provenance even though the real image
// (a trusted pinned OCI image) never gets evaluated.
func TestSR3_ContainerValueCarryingFlags(t *testing.T) {
	// containerValueCarryingFlags is a set of flags whose next arg is a value,
	// not the image reference. We test a representative subset here.
	valueFlags := []string{"-e", "--env", "-v", "--volume", "--name", "-p", "--publish",
		"-u", "--user", "--network", "-w", "--workdir", "--entrypoint",
		"-l", "--label", "--mount", "-h", "--hostname", "--log-driver",
		"--log-opt", "--cidfile"}
	for _, flag := range valueFlags {
		if !isContainerValueFlag(flag) {
			t.Errorf("isContainerValueFlag(%q) = false, want true", flag)
		}
	}
	// Non-value flags must NOT be treated as value-carrying.
	nonValueFlags := []string{"--rm", "-i", "--interactive", "-t", "--tty", "-d", "--detach"}
	for _, flag := range nonValueFlags {
		if isContainerValueFlag(flag) {
			t.Errorf("isContainerValueFlag(%q) = true, want false", flag)
		}
	}
}

// TestSR3_MCP006_ValueFlagArgsSkipped is the integration test for SR-3:
// `docker run -e FOO=BAR --name x -v /h:/c <trusted-pinned-image>` must NOT
// fire MCP006 because the value args (FOO=BAR, x, /h:/c) must be skipped and
// the real image reference evaluated.
func TestSR3_MCP006_ValueFlagArgsSkipped(t *testing.T) {
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	trustedImage := "ghcr.io/modelcontextprotocol/server-git@sha256:" + sha
	untrustedImage := "docker.io/evil/mcp@sha256:" + sha

	tests := []struct {
		name     string
		args     map[string]string
		wantFail bool
	}{
		{
			// SR-3: -e FOO=BAR before trusted pinned image must NOT flag.
			// Before fix: FOO=BAR was treated as the image ref → false positive.
			name: "SR-3 docker run -e FOO=BAR trusted-pinned-image must NOT flag",
			args: map[string]string{
				"mcpServers.s.command": "docker",
				"mcpServers.s.args.0":  "run",
				"mcpServers.s.args.1":  "--rm",
				"mcpServers.s.args.2":  "-e",
				"mcpServers.s.args.3":  "FOO=BAR",
				"mcpServers.s.args.4":  trustedImage,
			},
			wantFail: false,
		},
		{
			// SR-3: --name x before trusted pinned image must NOT flag.
			name: "SR-3 docker run --name x trusted-pinned-image must NOT flag",
			args: map[string]string{
				"mcpServers.s.command": "docker",
				"mcpServers.s.args.0":  "run",
				"mcpServers.s.args.1":  "--rm",
				"mcpServers.s.args.2":  "--name",
				"mcpServers.s.args.3":  "mycontainer",
				"mcpServers.s.args.4":  trustedImage,
			},
			wantFail: false,
		},
		{
			// SR-3: -v /h:/c before trusted pinned image must NOT flag.
			name: "SR-3 docker run -v /h:/c trusted-pinned-image must NOT flag",
			args: map[string]string{
				"mcpServers.s.command": "docker",
				"mcpServers.s.args.0":  "run",
				"mcpServers.s.args.1":  "--rm",
				"mcpServers.s.args.2":  "-v",
				"mcpServers.s.args.3":  "/host:/container",
				"mcpServers.s.args.4":  trustedImage,
			},
			wantFail: false,
		},
		{
			// SR-3: multiple value-carrying flags before trusted image must NOT flag.
			name: "SR-3 docker run -e X=1 --name c -v /h:/c trusted-pinned-image must NOT flag",
			args: map[string]string{
				"mcpServers.s.command": "docker",
				"mcpServers.s.args.0":  "run",
				"mcpServers.s.args.1":  "--rm",
				"mcpServers.s.args.2":  "-e",
				"mcpServers.s.args.3":  "X=1",
				"mcpServers.s.args.4":  "--name",
				"mcpServers.s.args.5":  "mycontainer",
				"mcpServers.s.args.6":  "-v",
				"mcpServers.s.args.7":  "/h:/c",
				"mcpServers.s.args.8":  trustedImage,
			},
			wantFail: false,
		},
		{
			// Regression: untrusted image after value-carrying flags must STILL flag.
			name: "SR-3 docker run -e X=1 untrusted-image must flag",
			args: map[string]string{
				"mcpServers.s.command": "docker",
				"mcpServers.s.args.0":  "run",
				"mcpServers.s.args.1":  "--rm",
				"mcpServers.s.args.2":  "-e",
				"mcpServers.s.args.3":  "X=1",
				"mcpServers.s.args.4":  untrustedImage,
			},
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &model.ScanContext{Collector: &model.Signals{
				Configs: []model.ConfigFact{{
					Source:   "~/Library/Application Support/Claude/claude_desktop_config.json",
					SchemaID: "claude-desktop-config", SchemaKnown: true,
					Values: tt.args,
				}},
			}}
			findings := run006(ctx)
			hasFail := false
			for _, f := range findings {
				if !f.Passed && f.Severity == model.SeverityWarning {
					hasFail = true
				}
			}
			if tt.wantFail != hasFail {
				t.Fatalf("wantFail=%v got hasFail=%v findings=%+v", tt.wantFail, hasFail, findings)
			}
		})
	}
}

// TestContainerRuntimeSubcommandSkip covers SF-4 (a): docker/podman run-subcommand skip.
func TestContainerRuntimeSubcommandSkip(t *testing.T) {
	const sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	// isContainerRuntime helpers
	runtimes := []string{"docker", "podman", "nerdctl"}
	for _, rt := range runtimes {
		if !isContainerRuntime(rt) {
			t.Errorf("isContainerRuntime(%q) = false, want true", rt)
		}
	}
	if isContainerRuntime("npx") {
		t.Errorf("isContainerRuntime(npx) = true, want false")
	}

	// isContainerSubcommand or flag
	subcommands := []string{"run", "exec", "create", "start", "pull", "push", "build", "--rm", "-i", "--interactive"}
	for _, s := range subcommands {
		if !isContainerSubcmdOrFlag(s) {
			t.Errorf("isContainerSubcmdOrFlag(%q) = false, want true", s)
		}
	}
	// an OCI image ref is not a subcommand
	if isContainerSubcmdOrFlag("ghcr.io/modelcontextprotocol/server-git@sha256:" + sha) {
		t.Errorf("OCI image ref should not be treated as subcommand/flag")
	}
}
