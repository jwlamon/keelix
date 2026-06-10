package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jakelamon/keelix/internal/engine"
	"github.com/jakelamon/keelix/internal/model"
)

// scanFlags holds the flags shared by commands that run a scan.
type scanFlags struct {
	compose       string
	host          string
	env           string
	firewall      string
	proxyConfig   string
	domains       string
	intendedPorts string
	noProbe       bool
	ai            bool
	timeout       time.Duration
	verbose       bool
	policy        string
	brandName     string

	collect           bool
	collectPrivileged bool
	signals           string

	noCollect bool

	probeMCP            bool
	probeMCPYes         bool
	probeMCPUnsandboxed bool
}

func (f *scanFlags) input() (engine.Input, error) {
	// A run with neither a compose file nor a signals file is the local
	// "quickstart": assess just this box. Collection is on by default (the
	// inside-out signals power the host/AI/MCP posture); --no-collect opts out.
	quickstart := f.compose == "" && f.signals == ""
	effectiveCollect := f.collect || (quickstart && !f.noCollect)
	if quickstart && !effectiveCollect {
		return engine.Input{}, fmt.Errorf("nothing to assess: pass -c <compose>, --signals <file>, or drop --no-collect to scan this box")
	}
	if f.compose != "" {
		if _, err := os.Stat(f.compose); err != nil {
			return engine.Input{}, fmt.Errorf("compose file not found: %s", f.compose)
		}
	}
	// Outside-in probing needs a target host; with none, scan inside-out only.
	noProbe := f.noProbe || f.host == ""

	ports, err := parseInts(f.intendedPorts)
	if err != nil {
		return engine.Input{}, fmt.Errorf("--intended-ports: %w", err)
	}
	timeout := f.timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	var logger model.Logger = model.NopLogger{}
	if f.verbose {
		logger = stderrLogger{}
	}
	return engine.Input{
		ComposePath:       f.compose,
		EnvPath:           f.env,
		FirewallPath:      f.firewall,
		ProxyConfigPath:   f.proxyConfig,
		Logger:            logger,
		Collect:           effectiveCollect,
		CollectPrivileged: f.collectPrivileged,
		SignalsPath:       f.signals,
		Options: model.ScanOptions{
			Host:                f.host,
			Domains:             splitCSV(f.domains),
			NoProbe:             noProbe,
			ProbeTimeout:        timeout,
			AIEnabled:           f.ai,
			IntendedPorts:       ports,
			PolicyPath:          f.policy,
			BrandName:           f.brandName,
			ComposePath:         f.compose,
			Collect:             effectiveCollect,
			CollectPrivileged:   f.collectPrivileged,
			SignalsPath:         f.signals,
			MCPProbeEnabled:     f.probeMCP,
			MCPProbeConsent:     f.probeMCPYes,
			MCPProbeUnsandboxed: f.probeMCPUnsandboxed,
		},
	}, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInts(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

type stderrLogger struct{}

func (stderrLogger) Debugf(f string, a ...any) { fmt.Fprintf(os.Stderr, "[debug] "+f+"\n", a...) }
func (stderrLogger) Infof(f string, a ...any)  { fmt.Fprintf(os.Stderr, "[info] "+f+"\n", a...) }
func (stderrLogger) Warnf(f string, a ...any)  { fmt.Fprintf(os.Stderr, "[warn] "+f+"\n", a...) }

// colorEnabled decides whether ANSI color should be used.
func colorEnabled(noColor bool, w *os.File) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := w.Stat()
	if err != nil {
		return false
	}
	// Only colorize when writing to a terminal (character device).
	return fi.Mode()&os.ModeCharDevice != 0
}
