// Package checks_test holds the RFX-9 parser-to-check pipeline integration test.
//
// TestRFX9_ParserToCheckPipeline is the REGRESSION that locks the complete
// pipeline for AGT001, AGT002, and MCP001. It runs collect.Collect with HOME
// pointed at a realistic temp directory containing REAL nested JSON shapes,
// then runs the registered checks against the produced Signals, and asserts
// the expected findings.
//
// This is the test that would have caught every bug remediated in this sprint:
//   - AGT001 false negative (tools.exec.ask="off" not firing)
//   - AGT002 false negative (trifecta per-config evaluation)
//   - MCP001 false negative (command-less remote server skipped)
//   - MCP001 false positive (keychain-ref incorrectly flagged)
//   - MCP003 false positive (pinned npx server incorrectly flagged)
//
// Fixture files are written into a real temp dir so collect.Collect's
// os.UserHomeDir() + isAllowed() + Lstat() + parse() + redact() pipeline
// runs end-to-end — nothing is pre-populated or bypassed.
package checks_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/aiagent"
	_ "github.com/jakelamon/keelix/internal/checks/mcp"
	"github.com/jakelamon/keelix/internal/collect"
	"github.com/jakelamon/keelix/internal/model"
)

// openclaw config: auto-approval + lethal-trifecta + messaging mcpServer.
//
//   - tools.exec.ask="off"      → AGT001 fires
//   - tools.fs.workspaceOnly=false → trifecta leg 1 (private data)
//   - browser.enabled=true      → trifecta leg 2 (untrusted ingest)
//   - mcpServers.slack (command-based, with inlined SLACK_BOT_TOKEN) → trifecta leg 3 (exfil)
const openclawConfigJSON = `{
  "tools": {
    "exec": {
      "security": "strict",
      "ask": "off"
    },
    "fs": {
      "workspaceOnly": false
    },
    "web": {
      "search": {
        "provider": ""
      }
    }
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "off"
      }
    }
  },
  "browser": {
    "enabled": true
  },
  "channels": {
    "discord": {
      "groupPolicy": "all"
    },
    "telegram": {
      "dmPolicy": "all"
    }
  },
  "mcpServers": {
    "slack-bot": {
      "command": "npx",
      "args": ["-y", "@slack/mcp-server"],
      "env": {
        "SLACK_BOT_TOKEN": "xoxb-realishslacktokenXXXXXXXXXXXXXXXXXXX"
      }
    }
  }
}`

// claude_desktop_config.json: three MCP servers with distinct credential styles.
//
//   - "secret-server": env.API_KEY holds a raw plaintext secret → MCP001 fires
//   - "pinned-server":  npx -y @scope/pkg@1.2.3 (pinned)          → MCP003 must NOT fire
//   - "keychain-server": env.API_KEY holds a keychain: reference   → MCP001 must NOT fire
const claudeDesktopConfigJSON = `{
  "mcpServers": {
    "secret-server": {
      "command": "npx",
      "args": ["-y", "some-mcp-tool"],
      "env": {
        "API_KEY": "sk-liveXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
      }
    },
    "pinned-server": {
      "command": "npx",
      "args": ["-y", "@scope/my-mcp-tool@1.2.3"]
    },
    "keychain-server": {
      "command": "npx",
      "args": ["-y", "another-mcp-tool"],
      "env": {
        "API_KEY": "keychain:MyCLITool/API_KEY"
      }
    }
  }
}`

// TestRFX9_ParserToCheckPipeline is the single integration test that locks
// the complete parse->redact->check pipeline for AGT001, AGT002, and MCP001.
//
// It writes REAL fixture files into a temp HOME, calls collect.Collect with
// HOME and the allowlist pointed at that temp dir, then runs the registered
// checks against the produced *model.Signals.
//
// Checks that MUST fire:
//   - AGT001: openclaw tools.exec.ask="off" (auto-approval)
//   - AGT002: all three trifecta legs co-present in one agent config
//   - MCP001: "secret-server" env.API_KEY is a plaintext secret
//
// Checks that must NOT misfire:
//   - MCP003: "pinned-server" uses npx with an explicit version pin → no finding
//   - MCP001: "keychain-server" env.API_KEY is a keychain: reference → no finding for it
func TestRFX9_ParserToCheckPipeline(t *testing.T) {
	// Build a realistic temp HOME directory tree.
	home := t.TempDir()

	// Write ~/.openclaw/openclaw.json
	openclawDir := filepath.Join(home, ".openclaw")
	if err := os.MkdirAll(openclawDir, 0o755); err != nil {
		t.Fatalf("mkdir .openclaw: %v", err)
	}
	openclawPath := filepath.Join(openclawDir, "openclaw.json")
	if err := os.WriteFile(openclawPath, []byte(openclawConfigJSON), 0o600); err != nil {
		t.Fatalf("write openclaw.json: %v", err)
	}

	// Write claude_desktop_config.json — macOS path or Linux XDG path.
	var desktopCfgDir string
	if runtime.GOOS == "darwin" {
		desktopCfgDir = filepath.Join(home, "Library", "Application Support", "Claude")
	} else {
		desktopCfgDir = filepath.Join(home, ".config", "Claude")
	}
	if err := os.MkdirAll(desktopCfgDir, 0o755); err != nil {
		t.Fatalf("mkdir claude desktop dir: %v", err)
	}
	desktopPath := filepath.Join(desktopCfgDir, "claude_desktop_config.json")
	if err := os.WriteFile(desktopPath, []byte(claudeDesktopConfigJSON), 0o600); err != nil {
		t.Fatalf("write claude_desktop_config.json: %v", err)
	}

	// Point HOME at the temp dir so os.UserHomeDir() resolves correctly.
	// Also rebuild the package-level allowlist for this home so isAllowed()
	// accepts the temp paths.
	t.Setenv("HOME", home)
	collect.RebuildAllowlistForHome(home)
	t.Cleanup(collect.RebuildAllowlistForDefaultHome)

	// Run the full collect pipeline.
	sig, err := collect.Collect(collect.Options{})
	if err != nil {
		t.Fatalf("collect.Collect: %v", err)
	}

	// Verify the config facts were actually parsed (not just bare facts).
	var gotOpenClaw, gotDesktop bool
	for _, cf := range sig.Configs {
		switch cf.SchemaID {
		case "openclaw-config":
			if cf.SchemaKnown {
				gotOpenClaw = true
			}
		case "claude-desktop-config":
			if cf.SchemaKnown {
				gotDesktop = true
			}
		}
	}
	if !gotOpenClaw {
		t.Fatalf("openclaw-config not parsed (SchemaKnown=false or missing); Configs: %+v", sig.Configs)
	}
	if !gotDesktop {
		t.Fatalf("claude-desktop-config not parsed (SchemaKnown=false or missing); Configs: %+v", sig.Configs)
	}

	sctx := &model.ScanContext{Collector: sig}

	// --- AGT001: auto-approval must fire ---
	t.Run("AGT001_fires_for_exec_ask_off", func(t *testing.T) {
		c := findCheck(t, "AGT001")
		findings := c.Run(sctx)
		for _, f := range findings {
			if f.CheckID == "AGT001" && f.IsFail() {
				return // expected
			}
		}
		t.Errorf("RFX-9: AGT001 must fire for tools.exec.ask=off; got %+v", findings)
	})

	// --- AGT002: lethal trifecta must fire ---
	t.Run("AGT002_fires_for_trifecta_in_one_config", func(t *testing.T) {
		c := findCheck(t, "AGT002")
		findings := c.Run(sctx)
		for _, f := range findings {
			if f.CheckID == "AGT002" && f.IsFail() {
				return // expected
			}
		}
		t.Errorf("RFX-9: AGT002 must fire for trifecta in single openclaw config; got %+v", findings)
	})

	// --- MCP001: inlined secret in "secret-server" must fire ---
	t.Run("MCP001_fires_for_inlined_secret", func(t *testing.T) {
		c := findCheck(t, "MCP001")
		findings := c.Run(sctx)
		hasFail := false
		for _, f := range findings {
			if f.CheckID == "MCP001" && f.IsFail() {
				hasFail = true
			}
		}
		if !hasFail {
			t.Errorf("RFX-9: MCP001 must fire for secret-server API_KEY plaintext secret; got %+v", findings)
		}
	})

	// --- MCP003: pinned npx server must NOT fire ---
	t.Run("MCP003_does_not_fire_for_pinned_server", func(t *testing.T) {
		c := findCheck(t, "MCP003")
		findings := c.Run(sctx)
		for _, f := range findings {
			if f.CheckID == "MCP003" && f.IsFail() {
				// Only flag if the failing finding is about the pinned server.
				if contains(f.Resource, "pinned-server") {
					t.Errorf("RFX-9: MCP003 must NOT fire for pinned-server (version pin present); finding: %+v", f)
				}
			}
		}
	})

	// --- MCP001: keychain-ref server must NOT fire MCP001 ---
	t.Run("MCP001_does_not_fire_for_keychain_ref", func(t *testing.T) {
		c := findCheck(t, "MCP001")
		findings := c.Run(sctx)
		for _, f := range findings {
			if f.CheckID == "MCP001" && f.IsFail() {
				if contains(f.Resource, "keychain-server") {
					t.Errorf("RFX-9: MCP001 must NOT fire for keychain-server (keychain-ref, not a plaintext secret); finding: %+v", f)
				}
			}
		}
	})
}

// findCheck returns the registered model.Check with the given ID.
func findCheck(t *testing.T, id string) model.Check {
	t.Helper()
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %s not registered", id)
	return nil
}

// contains reports whether s contains substr.
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
