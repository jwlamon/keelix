package firewall

import (
	"strconv"
	"strings"

	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/correlate"
	"github.com/jakelamon/keelix/internal/model"
)

func init() { model.Register(&fw005{}) }

type fw005 struct{}

func (c *fw005) ID() string              { return catalog.Get("FW005").ID }
func (c *fw005) Title() string           { return catalog.Get("FW005").Title }
func (c *fw005) Group() model.CheckGroup { return catalog.Get("FW005").Group }

func (c *fw005) Run(ctx *model.ScanContext) []model.Finding {
	if ctx.Collector == nil {
		return []model.Finding{notAssessed("FW005")}
	}
	if ctx.Collector.Platform.OS == "darwin" {
		return []model.Finding{notAssessed("FW005")}
	}

	// Path 1: scan dockerd process args for -H tcp://<non-loopback>.
	for _, proc := range ctx.Collector.Processes {
		if proc.Comm != "dockerd" {
			continue
		}
		for i, arg := range proc.Args {
			if arg == "-H" && i+1 < len(proc.Args) {
				if addr, ok := tcpNonLoopback(proc.Args[i+1]); ok {
					return []model.Finding{fw005Finding(addr)}
				}
			}
			// Also handle the combined form -H=tcp://...
			if strings.HasPrefix(arg, "-H=") {
				if addr, ok := tcpNonLoopback(arg[3:]); ok {
					return []model.Finding{fw005Finding(addr)}
				}
			}
		}
	}

	// Path 2: docker-daemon ConfigFact (daemon.json).
	cf, ok := configBySchema(ctx.Collector, "docker-daemon")
	if ok {
		if hosts, present := cf.Values["hosts"]; present {
			// hosts is a comma-separated list of address entries (e.g.
			// "unix:///var/run/docker.sock,tcp://0.0.0.0:2375").
			for _, h := range strings.Split(hosts, ",") {
				h = strings.TrimSpace(h)
				if addr, ok := tcpNonLoopback(h); ok {
					return []model.Finding{fw005Finding(addr)}
				}
			}
		}
	}

	return []model.Finding{catalog.Get("FW005").Pass("Docker daemon is not exposing a TCP API on a non-loopback address.")}
}

// tcpNonLoopback returns the raw address and true when addr is a tcp:// URI
// whose host is not a loopback address (127.0.0.1, ::1, localhost).
func tcpNonLoopback(addr string) (string, bool) {
	if !strings.HasPrefix(addr, "tcp://") {
		return "", false
	}
	hostPort := addr[len("tcp://"):]
	// Extract host: handle [::1]:port and host:port forms.
	host := hostPort
	if idx := strings.LastIndex(hostPort, ":"); idx >= 0 {
		host = hostPort[:idx]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return "", false
	}
	return addr, true
}

// fw005Finding builds the failing Finding for a confirmed non-loopback TCP exposure.
// ExposureClass is derived from the bind address via correlate.BindClass so that
// overlay/tailnet binds (e.g. tcp://100.64.x.x:2375) do not produce a false
// ExposureInternet (RED) — they produce ExposureOverlay instead.
func fw005Finding(addr string) model.Finding {
	f := catalog.Get("FW005").Finding()
	f.Resource = "dockerd"
	f.ExposureClass = correlate.BindClass(bindHostOf(addr))
	f.Evidence = "dockerd is listening on " + addr + " — the Docker API is reachable over TCP without requiring a host firewall to protect it"
	f.Metadata = map[string]string{"port": extractPort(addr, "2375")}
	f.Fix = model.Fix{
		Summary: "Remove the -H tcp:// flag from the Docker daemon and use Unix socket only. If remote API access is required, protect it with TLS mutual authentication and bind to a specific interface.",
		Commands: []string{
			"# Remove tcp:// from /etc/docker/daemon.json hosts or the dockerd systemd override",
			"systemctl restart docker",
		},
	}
	return f
}

// bindHostOf extracts the host portion from a tcp:// URI.
// It handles both [::1]:port (bracketed IPv6) and host:port forms.
// An empty host (e.g. "tcp://:2375", Docker's documented wildcard form)
// is treated as "0.0.0.0" so that BindClass correctly returns ExposureInternet
// rather than ExposureUnknown (R2-5 fix).
// Returns "" for non-tcp URIs or unparseable addresses.
func bindHostOf(addr string) string {
	if !strings.HasPrefix(addr, "tcp://") {
		return ""
	}
	hostPort := addr[len("tcp://"):]
	host := hostPort
	if idx := strings.LastIndex(hostPort, ":"); idx >= 0 {
		host = hostPort[:idx]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "0.0.0.0"
	}
	return host
}

// extractPort extracts the port from a tcp:// URI, returning def when absent.
func extractPort(addr, def string) string {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		p := addr[idx+1:]
		if _, err := strconv.Atoi(p); err == nil {
			return p
		}
	}
	return def
}
