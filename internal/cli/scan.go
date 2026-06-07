package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jwlamon/keelix/internal/engine"
	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/report"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		sf        scanFlags
		asJSON    bool
		noColor   bool
		ci        bool
		baseline  string
		reportFmt string
		output    string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan this box (and optionally a Compose stack) and print a scored posture report",
		Long: `Scan assesses the whole box — host OS, containers, services, and AI-agent/MCP
posture — and prints a single scored verdict. Run with no arguments to scan just
this machine; pass -c to also audit a Compose stack, and -H to probe a host from
the outside.

Examples:
  keelix scan                                  # whole-box posture of this machine
  keelix scan -c docker-compose.yml            # also audit a Compose stack
  keelix scan -c docker-compose.yml -H myserver.example.com
  keelix scan --no-collect -c docker-compose.yml --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			in, err := sf.input()
			if err != nil {
				return err
			}
			if ci {
				in.Options.CI = true
			}
			if in.Options.CI {
				// CI is never a TTY; do not prompt. Force the non-interactive path.
				in.Options.MCPProbeConsent = in.Options.MCPProbeConsent && in.Options.MCPProbeEnabled
			}
			// §5.3: machine-readable output modes (--json, --report) are
			// non-interactive by definition. Never prompt for MCP probe consent
			// when the operator has requested non-interactive output; refuse
			// unless --probe-mcp-yes was also supplied.
			nonInteractive := asJSON || reportFmt != "" || !stdinIsTTY()
			if in.Options.MCPProbeEnabled {
				commands := engine.PlannedMCPProbeCommands(in)
				applyMCPConsentWith(&in, !nonInteractive, commands, os.Stdin, cmd.ErrOrStderr())
			}
			result, err := engine.Scan(context.Background(), in)
			if err != nil {
				return err
			}

			switch {
			case asJSON:
				if err := writeJSON(result, output); err != nil {
					return err
				}
			case reportFmt != "":
				if err := writeReport(result, reportFmt, output); err != nil {
					return err
				}
			default:
				_ = report.Terminal(os.Stdout, result, colorEnabled(noColor, os.Stdout))
			}

			if ci {
				return ciExit(result, baseline)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&sf.compose, "compose", "c", "", "path to docker-compose.yml (optional; omit to scan just this box)")
	f.StringVarP(&sf.host, "host", "H", "", "target host to probe outside-in")
	f.StringVar(&sf.env, "env", "", "path to a .env file (auto-detected next to compose if omitted)")
	f.StringVar(&sf.firewall, "firewall", "", "path to a UFW/iptables rules dump to correlate")
	f.StringVar(&sf.proxyConfig, "proxy-config", "", "path to a reverse-proxy config (Caddyfile/nginx.conf/traefik.yml)")
	f.StringVar(&sf.domains, "domains", "", "comma-separated extra domains to resolve")
	f.StringVar(&sf.intendedPorts, "intended-ports", "", "comma-separated ports you intend to expose publicly")
	f.BoolVar(&sf.noProbe, "no-probe", false, "disable outside-in probing (static analysis only)")
	f.BoolVar(&sf.ai, "ai", false, "enrich findings via the Claude API (needs ANTHROPIC_API_KEY)")
	f.DurationVar(&sf.timeout, "timeout", 0, "per-connection probe timeout (default 3s)")
	f.BoolVarP(&sf.verbose, "verbose", "v", false, "verbose progress on stderr")
	f.StringVar(&sf.policy, "policy", "", "path to a JSON policy file for org-defined custom checks")
	f.StringVar(&sf.brandName, "brand-name", "", "product name shown in reports (default \"Keelix\")")
	f.BoolVar(&sf.collect, "collect", false, "also gather inside-out host signals before scoring")
	f.BoolVar(&sf.noCollect, "no-collect", false, "skip inside-out host collection (use with -c/--signals only)")
	f.BoolVar(&sf.collectPrivileged, "collect-privileged", false, "with --collect, run privileged collectors")
	f.StringVar(&sf.signals, "signals", "", "path to a Signals JSON from 'keelix collect' to correlate")
	f.BoolVar(&sf.probeMCP, "probe-mcp", false, "run the consent-gated, sandboxed active MCP probe (executes untrusted MCP server code; off by default)")
	f.BoolVar(&sf.probeMCPYes, "probe-mcp-yes", false, "with --probe-mcp, consent non-interactively (required in CI/non-TTY)")
	f.BoolVar(&sf.probeMCPUnsandboxed, "probe-mcp-unsandboxed", false, "with --probe-mcp, disable the best-effort sandbox (diagnostic only)")
	cmd.MarkFlagsMutuallyExclusive("collect", "no-collect")
	f.BoolVar(&asJSON, "json", false, "output machine-readable JSON")
	f.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	f.BoolVar(&ci, "ci", false, "CI mode: exit non-zero when a critical finding is present")
	f.StringVar(&baseline, "baseline", "", "with --ci, a previous scan JSON; fail only on NEW criticals")
	f.StringVar(&reportFmt, "report", "", "write a posture report instead of the terminal view (md|html|pdf)")
	f.StringVarP(&output, "output", "o", "", "output file for --json or --report")
	return cmd
}

func writeJSON(r *model.Result, output string) error {
	if output == "" {
		return report.JSON(os.Stdout, r)
	}
	f, err := os.Create(output) // #nosec G304 -- output path is an operator-supplied CLI flag; local CLI writing the user's own file
	if err != nil {
		return err
	}
	defer f.Close()
	return report.JSON(f, r)
}

func writeReport(r *model.Result, format, output string) error {
	var render func(*os.File) error
	var defExt string
	switch format {
	case "md", "markdown":
		render, defExt = func(f *os.File) error { return report.Markdown(f, r) }, "md"
	case "html":
		render, defExt = func(f *os.File) error { return report.HTML(f, r) }, "html"
	case "pdf":
		render, defExt = func(f *os.File) error { return report.PDF(f, r) }, "pdf"
	default:
		return fmt.Errorf("unknown report format %q (want md|html|pdf)", format)
	}
	if output == "" {
		output = "keelix-report." + defExt
	}
	f, err := os.Create(output) // #nosec G304 -- output path is an operator-supplied CLI flag; local CLI writing the user's own file
	if err != nil {
		return err
	}
	defer f.Close()
	if err := render(f); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s report to %s\n", format, output)
	return nil
}

// ciExit returns a non-zero exit error when criticals are present (or, with a
// baseline, when NEW criticals appear vs. the baseline).
func ciExit(r *model.Result, baseline string) error {
	newCriticals := criticalKeys(r)
	if baseline != "" {
		base, err := loadResult(baseline)
		if err != nil {
			return exitError{code: 1, msg: fmt.Sprintf("reading baseline: %v", err)}
		}
		known := criticalKeys(base)
		var remaining []string
		for _, k := range newCriticals {
			if !contains(known, k) {
				remaining = append(remaining, k)
			}
		}
		newCriticals = remaining
	}
	if len(newCriticals) > 0 {
		return exitError{code: 2, msg: fmt.Sprintf("%d critical finding(s) present", len(newCriticals))}
	}
	return nil
}

func criticalKeys(r *model.Result) []string {
	var keys []string
	for _, f := range r.Findings {
		if f.Severity == model.SeverityCritical {
			keys = append(keys, f.CheckID+"|"+f.Service+"|"+f.Resource)
		}
	}
	return keys
}

func loadResult(path string) (*model.Result, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument; local CLI reading the user's own file
	if err != nil {
		return nil, err
	}
	var r model.Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// applyMCPConsentWith runs the consent gate and, on success, sets
// in.Options.MCPProbeConsent so the engine will run the active probe. It is the
// I/O-injected core used by both the scan command and tests.
func applyMCPConsentWith(in *engine.Input, isTTY bool, commands []string, stdin io.Reader, out io.Writer) {
	ok := resolveMCPConsent(consentEnv{
		enabled:   in.Options.MCPProbeEnabled,
		consented: in.Options.MCPProbeConsent,
		isTTY:     isTTY,
		commands:  commands,
	}, stdin, out)
	in.Options.MCPProbeConsent = ok && in.Options.MCPProbeEnabled
}

// stdinIsTTY reports whether stdin is an interactive terminal.
func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
