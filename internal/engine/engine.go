// Package engine orchestrates a full scan: parse the stack, infer intent,
// probe outside-in, run the deterministic check library, score the result, and
// optionally enrich it with the AI layer. Checks register themselves via
// init(); the caller is responsible for blank-importing internal/checks/all so
// the registry is populated.
package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/jwlamon/keelix/internal/ai"
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/collect"
	"github.com/jwlamon/keelix/internal/correlate"
	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/mcpprobe"
	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/parse"
	"github.com/jwlamon/keelix/internal/policy"
	"github.com/jwlamon/keelix/internal/probe"
	"github.com/jwlamon/keelix/internal/redact"
	"github.com/jwlamon/keelix/internal/sandbox"
	"github.com/jwlamon/keelix/internal/score"
	"github.com/jwlamon/keelix/internal/version"
)

// Input bundles everything a scan needs.
type Input struct {
	ComposePath     string
	EnvPath         string
	FirewallPath    string
	ProxyConfigPath string
	Options         model.ScanOptions
	Logger          model.Logger
	// Collect, CollectPrivileged, and SignalsPath are the CLI-flag counterparts
	// of Options.Collect / Options.CollectPrivileged / Options.SignalsPath.
	// They are wired into Options by the scan command and surfaced here so that
	// callers that build Input directly (e.g. the CLI layer) can read them back
	// without traversing Options.
	Collect           bool
	CollectPrivileged bool
	SignalsPath       string
}

// commonPorts are always probed in addition to declared + sensitive ports, so
// surprise web/admin exposure is caught even when not declared in Compose.
var commonPorts = []int{22, 80, 443, 3000, 8000, 8080, 8443, 8888, 9000}

// extraFindings is a test-only hook: when non-nil it appends synthetic findings
// after the check loop, letting tests exercise Result routing (e.g. NotAssessed)
// without a production check that emits that state. Always nil in normal builds.
var extraFindings func(*model.ScanContext) []model.Finding

// Scan runs the full pipeline and returns the assembled Result. It returns an
// error only for unrecoverable setup problems (e.g. the compose file cannot be
// read/parsed). Probing and AI failures are recorded but never abort the scan.
func Scan(ctx context.Context, in Input) (*model.Result, error) {
	log := in.Logger
	if log == nil {
		log = model.NopLogger{}
	}

	stack, err := parse.LoadStack(parse.Options{
		ComposePath:     in.ComposePath,
		EnvPath:         in.EnvPath,
		FirewallPath:    in.FirewallPath,
		ProxyConfigPath: in.ProxyConfigPath,
	})
	if err != nil {
		return nil, fmt.Errorf("parse stack: %w", err)
	}
	log.Infof("parsed %d services from %s", len(stack.Services), in.ComposePath)

	intended := correlate.BuildIntended(stack, in.Options)

	var pr *model.ProbeResult
	if !in.Options.NoProbe && in.Options.Host != "" {
		ports := candidatePorts(stack)
		log.Infof("probing %s across %d ports", in.Options.Host, len(ports))
		pr = probe.Probe(ctx, probe.Options{
			Host:        in.Options.Host,
			Domains:     in.Options.Domains,
			Ports:       ports,
			Timeout:     in.Options.ProbeTimeout,
			Concurrency: 50,
		})
	} else {
		log.Infof("outside-in probing disabled (static analysis only)")
	}

	var sig *model.Signals
	switch {
	case in.Options.SignalsPath != "":
		log.Infof("loading inside-out signals from %s", in.Options.SignalsPath)
		s, err := collect.Load(in.Options.SignalsPath)
		if err != nil {
			log.Warnf("collect: load %s: %v (continuing without inside-out facts)", in.Options.SignalsPath, err)
		} else {
			sig = s
		}
	case in.Options.Collect:
		log.Infof("collecting inside-out facts (privileged=%v)", in.Options.CollectPrivileged)
		s, err := collect.Collect(collect.Options{
			Privileged:     in.Options.CollectPrivileged,
			ServiceConfigs: collect.ServiceConfigCandidates(stack),
		})
		if err != nil {
			log.Warnf("collect: %v (continuing without inside-out facts)", err)
		} else {
			sig = s
		}
	default:
		log.Infof("inside-out collection disabled")
	}

	mcpProbe, mcpGateFindings := maybeProbeMCP(in.Options, sig, mcpBaselinePath())
	if mcpProbe != nil {
		if sig == nil {
			sig = &model.Signals{}
		}
		sig.MCPProbe = mcpProbe
		log.Infof("active MCP probe ran: %d server(s) reached", len(mcpProbe.Servers))
	}

	sctx := &model.ScanContext{
		Stack:     stack,
		Options:   in.Options,
		Probe:     pr,
		Collector: sig,
		Intended:  intended,
		Logger:    log,
	}

	var findings []model.Finding
	for _, c := range model.Registered() {
		fs := c.Run(sctx)
		findings = append(findings, fs...)
	}

	if extraFindings != nil {
		findings = append(findings, extraFindings(sctx)...)
	}

	// Include sandbox-gate findings from the MCP probe path (e.g. "probe
	// skipped: no sandbox available" or "running under Tier-0 only"). These
	// are emitted before any checks run so they are always present even when
	// no registered check covers the MCP probe gate.
	findings = append(findings, mcpGateFindings...)

	// Evaluate org-defined custom policy rules (emitted outside the registered-check
	// registry so the catalog↔registry guard test is unaffected).
	if in.Options.PolicyPath != "" {
		pol, err := policy.Load(in.Options.PolicyPath)
		if err != nil {
			log.Warnf("policy: %v (skipping custom policy evaluation)", err)
		} else {
			findings = append(findings, pol.Evaluate(stack)...)
		}
	}

	sortFindings(findings)

	// Classify exposure + compensating controls from observed facts (probe +
	// collector). Pure w.r.t. inputs; mutates each finding's ExposureClass and
	// Mitigations in place before scoring consumes them.
	correlate.Classify(findings, sctx)

	counts := score.Count(findings)
	sc, rating, subs, cap := score.ComputeV2(findings)
	var notAssessed []model.Finding
	for _, f := range findings {
		if f.Status == model.StatusNotAssessed {
			notAssessed = append(notAssessed, f)
		}
	}
	target := in.Options.Host
	if target == "" {
		target = stack.ProjectName
	}
	if target == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			target = h
		} else {
			target = "local"
		}
	}

	result := &model.Result{
		Target:       target,
		ScannedAt:    time.Now().UTC(),
		Version:      version.Version,
		Score:        sc,
		Rating:       rating,
		ScoringModel: "v2",
		SubScores:    subs,
		CapDriver:    cap,
		Counts:       counts,
		Findings:     findings,
		NotAssessed:  notAssessed,
		Stack:        stack,
		Probe:        pr,
		Collector:    sig,
		Methodology:  methodology(in.Options, sig),
		BrandName:    brand(in.Options),
	}

	// Redact secret values from all free-text fields BEFORE anything leaves the
	// core: this single seam protects the AI prompt, the rendered report, the
	// public /share page, and the JSON pushed to the cloud. Runs unconditionally
	// (privacy/security, not a paid gate).
	redact.Result(result)

	if in.Options.AIEnabled {
		client := ai.NewClient()
		if client.Enabled() {
			log.Infof("enriching findings via AI layer")
			if err := client.Enrich(ctx, result); err != nil {
				log.Warnf("AI enrichment degraded: %v", err)
			}
		} else {
			log.Warnf("AI enrichment requested but ANTHROPIC_API_KEY is not set; skipping")
		}
	}

	return result, nil
}

// candidatePorts is the union of declared host ports, all known sensitive
// ports, and common web/admin ports.
func candidatePorts(s *model.Stack) []int {
	set := map[int]struct{}{}
	for _, p := range commonPorts {
		set[p] = struct{}{}
	}
	for _, pi := range intel.SensitivePorts() {
		set[pi.Port] = struct{}{}
	}
	for _, svc := range s.Services {
		for _, pm := range svc.Ports {
			if pm.HostPort != 0 {
				set[pm.HostPort] = struct{}{}
			}
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// sortFindings orders findings by severity (critical first) then check ID for
// stable, prioritized output.
func sortFindings(f []model.Finding) {
	sevRank := func(s model.Severity) int {
		switch s {
		case model.SeverityCritical:
			return 0
		case model.SeverityWarning:
			return 1
		case model.SeverityInfo:
			return 2
		default:
			return 3
		}
	}
	sort.SliceStable(f, func(i, j int) bool {
		ri, rj := sevRank(f[i].Severity), sevRank(f[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return f[i].CheckID < f[j].CheckID
	})
}

// collectForPlanning loads the inside-out signals the consent prompt needs to
// enumerate MCP servers, WITHOUT running the active probe. It reuses the same
// precedence as Scan (SignalsPath > Collect) and silently returns nil on error.
func collectForPlanning(in Input) *model.Signals {
	switch {
	case in.Options.SignalsPath != "":
		s, err := collect.Load(in.Options.SignalsPath)
		if err != nil {
			return nil
		}
		return s
	case in.Options.Collect:
		// TODO: ServiceConfigs are skipped in the planning path because
		// collectForPlanning does not receive a *model.Stack. Pass stack here
		// once the consent-prompt path is refactored to accept one.
		s, err := collect.Collect(collect.Options{Privileged: in.Options.CollectPrivileged})
		if err != nil {
			return nil
		}
		return s
	default:
		return nil
	}
}

// maybeProbeMCP runs the consent-gated, sandboxed active MCP probe and returns
// its result plus any sandbox-gate findings. It returns (nil, nil) when the
// probe is not enabled/consented or no servers were found.
//
// SBX-5 gate: before spawning untrusted code, this function checks whether a
// real kernel-level sandbox tier (Landlock on linux, Seatbelt on darwin) is
// available on the host via sandbox.Available(). It delegates to the
// inner helper maybeProbeMCPInner for testability.
func maybeProbeMCP(opts model.ScanOptions, sig *model.Signals, baselinePath string) (*model.MCPProbe, []model.Finding) {
	return maybeProbeMCPInner(opts, sig, baselinePath, sandbox.Available(), sandbox.NewRunner())
}

// maybeProbeMCPInner is the testable core of maybeProbeMCP. sandboxAvailable
// is the result of sandbox.Available(); runner is the sandbox.Runner to use
// when the probe is allowed to spawn.
//
// SBX-5 gate: when sandboxAvailable is false and opts.MCPProbeUnsandboxed is
// false (the default), the probe is downgraded to inventory-only (no spawn)
// and an info finding is returned. When MCPProbeUnsandboxed is true the probe
// proceeds under Tier-0 hygiene and a warning finding is returned.
func maybeProbeMCPInner(opts model.ScanOptions, sig *model.Signals, baselinePath string, sandboxAvailable bool, runner sandbox.Runner) (*model.MCPProbe, []model.Finding) {
	if !opts.MCPProbeEnabled || !opts.MCPProbeConsent {
		return nil, nil
	}
	specs := deriveServerSpecs(sig)
	if len(specs) == 0 {
		return nil, nil
	}

	// SBX-5: gate on real sandbox availability before spawning untrusted code.
	if !sandboxAvailable {
		if !opts.MCPProbeUnsandboxed {
			// No real tier available and the operator has not opted in to
			// Tier-0-only execution. Downgrade to inventory-only: do not spawn.
			return nil, []model.Finding{{
				CheckID:  "MCP000",
				Group:    model.GroupMCP,
				Severity: model.SeverityInfo,
				Title:    "MCP active probe skipped: no sandbox available",
				Detail: "The active MCP probe requires a real kernel-level sandbox (Landlock on Linux, Seatbelt on macOS). " +
					"No supported isolation tier was detected on this host. " +
					"Pass --probe-mcp-unsandboxed to run the probe under Tier-0 process hygiene only (clean env, throwaway dir, pgid kill — no kernel confinement).",
				Status: model.StatusNotAssessed,
			}}
		}
		// Operator explicitly opted in to Tier-0-only execution. Proceed but
		// emit a warning so the weaker isolation is visible in the report.
		probe := mcpprobe.Probe(specs, runner, baselinePath, time.Now().UTC())
		return probe, []model.Finding{{
			CheckID:  "MCP000",
			Group:    model.GroupMCP,
			Severity: model.SeverityWarning,
			Title:    "MCP active probe running without kernel sandbox (--probe-mcp-unsandboxed)",
			Detail: "The active MCP probe is executing untrusted MCP server code under Tier-0 process hygiene only " +
				"(clean env, throwaway tempdir, pgid kill). No kernel-level confinement (Landlock/Seatbelt) is available " +
				"on this host. This reduces the isolation guarantee: a malicious server could attempt host-level attacks " +
				"that kernel confinement would have blocked.",
		}}
	}

	return mcpprobe.Probe(specs, runner, baselinePath, time.Now().UTC()), nil
}

// mcpBaselinePath returns the on-disk path for the MCP tool-description baseline
// (~/.keelix/mcp-baseline.json). On failure it returns an empty string, which
// the probe treats as "no baseline" (first-run inventory only).
func mcpBaselinePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".keelix", "mcp-baseline.json")
}

// brand returns the human-facing product name: opts.BrandName if set, else "Keelix".
func brand(opts model.ScanOptions) string {
	if opts.BrandName != "" {
		return opts.BrandName
	}
	return "Keelix"
}

// signalsDomains returns a human-readable list of the signal domains that were
// actually populated in sig, plus any domains that reported collection errors.
// An empty slice means no useful inside-out data was gathered.
func signalsDomains(sig *model.Signals) []string {
	if sig == nil {
		return nil
	}
	var domains []string
	if len(sig.Sockets) > 0 {
		domains = append(domains, "listening sockets")
	}
	if len(sig.Files) > 0 {
		domains = append(domains, "file facts")
	}
	if len(sig.Configs) > 0 {
		domains = append(domains, "config facts")
	}
	if len(sig.Processes) > 0 {
		domains = append(domains, "process facts")
	}
	if sig.Packages.Manager != "" || sig.Packages.SecurityUpdatesPending > 0 ||
		sig.Packages.RebootRequired || sig.Packages.DistroEOL {
		domains = append(domains, "package state")
	}
	if sig.Firewall.Backend != "" {
		domains = append(domains, "firewall state")
	}
	// Also include domains that attempted collection but errored, so the
	// methodology is honest about what was tried.
	for _, ce := range sig.Errors {
		// Avoid duplicating a domain already listed above.
		found := false
		for _, d := range domains {
			if d == ce.Domain {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, ce.Domain+" (partial)")
		}
	}
	return domains
}

func methodology(opts model.ScanOptions, sig *model.Signals) string { //nolint:revive // sig also carries the optional MCP probe summary
	b := brand(opts)
	var m string
	noCompose := opts.ComposePath == ""
	if noCompose {
		m = b + " performed a deterministic inside-out assessment of the local host. " +
			"The pipeline collects inside-out host signals and runs the full check library against those signals "
		if opts.NoProbe || opts.Host == "" {
			m += "to evaluate host-level security posture (outside-in probing was disabled for this run). "
		} else {
			m += "and probes the target from an external vantage point to corroborate exposure, evaluating host-level security posture. "
		}
	} else {
		m = b + " performed a deterministic, static-plus-dynamic assessment of the target's Docker Compose deployment. " +
			"The pipeline parses the Compose file (and any provided .env, reverse-proxy and firewall configuration), infers which ports are intended to be public, "
		if opts.NoProbe || opts.Host == "" {
			m += "and evaluates the full check library against the declared configuration (outside-in probing was disabled for this run). "
		} else {
			m += "probes the target from an external vantage point to establish which ports are actually reachable, correlates declared-vs-reachable-vs-intended exposure, and evaluates the full check library. "
		}
	}
	domains := signalsDomains(sig)
	if len(domains) > 0 {
		priv := "unprivileged"
		if sig.Privilege.Root {
			priv = "privileged"
		}
		// Build a human-readable list of the domains that were actually collected.
		domainList := domains[0]
		for i := 1; i < len(domains)-1; i++ {
			domainList += ", " + domains[i]
		}
		if len(domains) > 1 {
			domainList += ", and " + domains[len(domains)-1]
		}
		m += "inside-out collection ran on the host (" + priv + "), capturing " + domainList + " to corroborate exposure. "
	} else {
		m += "inside-out collection was not performed for this run (outside-in and static analysis only). "
	}
	m += "All security findings are produced by deterministic checks; the optional AI layer only enriches human-readable explanations and never affects detection or scoring. " +
		"Findings are mapped to SOC 2 Trust Services Criteria, ISO 27001 Annex A (2022), and the CIS Docker Benchmark using check catalog v" + catalog.CatalogVersion + "."
	if sig != nil && sig.MCPProbe != nil {
		tier := "tier0"
		anyApplied := false
		for _, s := range sig.MCPProbe.Servers {
			if s.SandboxTier != "" && s.SandboxTier != "http" {
				tier = s.SandboxTier
			}
			if s.SandboxApplied {
				anyApplied = true
			}
		}
		confinement := "Tier-0 process hygiene only (clean env, tempdir, pgid isolation; no kernel confinement verified)"
		if anyApplied {
			confinement = "kernel confinement verified (tier: " + tier + ")"
		}
		m += "The consent-gated active MCP probe also ran, connecting to declared MCP servers under " + confinement + ", to inventory tool descriptions and detect tool-poisoning/rug-pull drift against the recorded baseline. "
	}
	return m
}
