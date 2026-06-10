package correlate

import (
	"net"
	"strconv"
	"strings"

	"github.com/jakelamon/keelix/internal/model"
)

// findingPort resolves the TCP port a finding concerns. It first reads
// f.Metadata["port"], then falls back to parsing f.Resource of the form
// "port <n>". ok is false when neither yields a positive integer.
func findingPort(f model.Finding) (int, bool) {
	if f.Metadata != nil {
		if raw, ok := f.Metadata["port"]; ok {
			if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
				return n, true
			}
		}
	}
	res := strings.TrimSpace(f.Resource)
	if strings.HasPrefix(res, "port ") {
		if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(res, "port "))); err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}

// prevBand returns the exposure class one band lower (less exposed) than e,
// floored at ExposureLocalhost. ExposureUnknown has no defined lower band and
// is returned unchanged.
func prevBand(e model.ExposureClass) model.ExposureClass {
	switch e {
	case model.ExposureInternet:
		return model.ExposureFiltered
	case model.ExposureFiltered:
		return model.ExposureLAN
	case model.ExposureLAN:
		return model.ExposureOverlay
	case model.ExposureOverlay:
		return model.ExposureLocalhost
	default:
		// ExposureLocalhost is the floor; ExposureUnknown has no lower band.
		return e
	}
}

// BindClass maps a bind address to its exposure class, independent of probe
// confirmation. A wildcard bind ("0.0.0.0"/"::") or a public IP literal
// classifies as ExposureInternet; this is later downgraded to ExposureFiltered
// by classifyOne when the probe could not confirm the port open.
// It is exported so that in-check classifiers (e.g. FW005, FW006) can derive
// an accurate ExposureClass directly from the bind address they observe,
// without waiting for the port-based correlator.
func BindClass(bind string) model.ExposureClass { return bindClass(bind) }

// bindClass is the unexported implementation; callers inside the package use it
// directly, external checks use the exported BindClass wrapper.
func bindClass(bind string) model.ExposureClass {
	bind = strings.TrimSpace(bind)
	if bind == "" {
		return model.ExposureUnknown
	}
	if bind == "0.0.0.0" || bind == "::" {
		return model.ExposureInternet
	}
	ip := net.ParseIP(bind)
	if ip == nil {
		return model.ExposureUnknown
	}
	if ip.IsLoopback() {
		return model.ExposureLocalhost
	}
	// Link-local (169.254.0.0/16 for IPv4, fe80::/10 for IPv6) is LAN-scoped.
	if ip.IsLinkLocalUnicast() {
		return model.ExposureLAN
	}
	// 100.64.0.0/10 (RFC6598 CGNAT, used by Tailscale/overlay tailnets).
	if cgnat := (net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}); cgnat.Contains(ip) {
		return model.ExposureOverlay
	}
	if ip.IsPrivate() {
		return model.ExposureLAN
	}
	// Any other routable literal binds the service to a public-facing address.
	return model.ExposureInternet
}

// maxBindClass returns the maximum (most exposed) ExposureClass across all
// sockets on the given port. When probeOpen is true and the max class is
// ExposureInternet, it is kept; otherwise Internet is downgraded to
// ExposureFiltered. This ensures a dual-bound 127.0.0.1+0.0.0.0 service
// classifies by its most-exposed socket.
func maxBindClass(s *model.Signals, port int, probeOpen bool) model.ExposureClass {
	max := model.ExposureUnknown
	for _, sock := range s.Sockets {
		if sock.Port != port {
			continue
		}
		c := bindClass(sock.Bind)
		if c > max {
			max = c
		}
	}
	if max == model.ExposureInternet && !probeOpen {
		max = model.ExposureFiltered
	}
	return max
}

// Classify mutates each finding's ExposureClass (and, in a later pass,
// Mitigations) from observed facts. It is pure with respect to its inputs and
// performs no I/O. Passing findings (Severity == SeverityOK) are left untouched.
//
// Base exposure is resolved per finding in priority order:
//  1. collector socket bind   (max ExposureClass over all sockets on the port)
//  2. outside-in reachability (sctx.Probe.IsReachable)
//  3. declared/intended       (sctx.Stack + sctx.Intended): a host port published
//     to ALL interfaces that is NOT in sctx.Intended => ExposureInternet; if it
//     IS intended-public => ExposureFiltered (intent says public but mitigated).
//     Returns ExposureUnknown when nothing is known.
//
// A wildcard ("0.0.0.0"/"::") bind classifies as ExposureInternet only when the
// probe confirms the port open; otherwise it is downgraded to ExposureFiltered.
//
// Findings whose ExposureClass is already non-Unknown (i.e. was set by the check
// itself before returning) are skipped entirely. This covers two cases:
//   - DomainAIMCP checks (AGT/MCP groups) which set ExposureClass in-check
//     (e.g. ExposureLocalhost for config-only findings, or a bind-derived class
//     for network-reachable AGT006/MCP004) — port-based classification does not
//     apply to that domain.
//   - Any other check (e.g. HST003) that self-classifies based on its own socket
//     evidence rather than the port-oriented correlator.
//
// Port-based classification must not overwrite an in-check ExposureClass.
func Classify(findings []model.Finding, sctx *model.ScanContext) {
	for i := range findings {
		if findings[i].Severity == model.SeverityOK {
			continue
		}
		// Skip findings whose ExposureClass is already non-Unknown: the check
		// set it in-check and the correlator must not overwrite it. This covers
		// DomainAIMCP checks (AGT/MCP) that classify per-finding in-check, and
		// any other check (e.g. HST003) that self-classifies from its own evidence.
		if model.DomainOf(findings[i].Group) == model.DomainAIMCP || findings[i].ExposureClass != model.ExposureUnknown {
			continue
		}
		classifyOne(&findings[i], sctx)
	}
}

// hostPortFor returns the host (published) port that maps to containerPort in
// the stack. It searches all services and their port mappings for an unambiguous
// match: if exactly one mapping exists for containerPort it returns the
// corresponding HostPort; if zero or more than one mapping exists (ambiguous)
// it returns 0. This allows classifyOne to use the effective host port for
// socket/probe/declaredPublic lookups when the publish is asymmetric
// (e.g. "18989:8989").
func hostPortFor(stack *model.Stack, containerPort int) int {
	if stack == nil {
		return 0
	}
	found := 0
	hostPort := 0
	for _, svc := range stack.Services {
		for _, pm := range svc.Ports {
			if pm.ContainerPort == containerPort {
				found++
				hostPort = pm.HostPort
			}
		}
	}
	if found == 1 {
		return hostPort
	}
	return 0
}

// hostPortsFor returns all host ports that map to containerPort in the stack.
// Unlike hostPortFor, it does not return 0 on ambiguous matches — it returns
// every mapped host port so that classifyOne can union over all candidates and
// pick the most-exposed class. An empty slice means the container port is not
// published on any host port. Duplicate host ports (same HostPort from different
// services) are deduplicated.
func hostPortsFor(stack *model.Stack, containerPort int) []int {
	if stack == nil {
		return nil
	}
	seen := make(map[int]bool)
	var result []int
	for _, svc := range stack.Services {
		for _, pm := range svc.Ports {
			if pm.ContainerPort == containerPort && pm.HostPort > 0 {
				if !seen[pm.HostPort] {
					seen[pm.HostPort] = true
					result = append(result, pm.HostPort)
				}
			}
		}
	}
	return result
}

// classifyOne sets one finding's ExposureClass from observed facts, then applies
// compensating controls that may collapse the class one band lower.
//
// When the stack declares a port publish (including asymmetric, e.g. "18989:8989"),
// classifyOne collects all mapped host ports via hostPortsFor and unions over
// all candidates (most-exposed wins). This handles both the unambiguous case
// (one host port) and the ambiguous case (multiple services publishing the same
// container port on different host ports). The container port is the final
// fallback when no host-port mappings are found.
func classifyOne(f *model.Finding, sctx *model.ScanContext) {
	port, ok := findingPort(*f)
	if !ok {
		f.ExposureClass = model.ExposureUnknown
		return
	}

	var probe *model.ProbeResult
	var collector *model.Signals
	var stack *model.Stack
	if sctx != nil {
		probe = sctx.Probe
		collector = sctx.Collector
		stack = sctx.Stack
	}

	// Resolve candidate ports: collect all mapped host ports from the stack.
	// When the publish is symmetric (7878:7878) or asymmetric (18989:8989),
	// we get exactly one host port. When multiple services share the same
	// container port (ambiguous), we get all of them. When no publish exists
	// we fall back to the container port itself.
	candidates := hostPortsFor(stack, port)
	if len(candidates) == 0 {
		candidates = []int{port}
	}

	// Union over all candidate host ports: probe, socket, and declared-public
	// lookups are all performed against each candidate. The most-exposed class
	// found across all candidates is chosen (most-exposed wins).
	best := model.ExposureUnknown
	bestEffective := candidates[0]
	bestProbeOpen := false
	for _, effectivePort := range candidates {
		probeOpen := probe.IsReachable(effectivePort)

		var ec model.ExposureClass
		switch {
		case collector != nil && socketFound(collector, effectivePort):
			ec = maxBindClass(collector, effectivePort, probeOpen)
		case probe != nil:
			if probeOpen {
				ec = model.ExposureInternet
			} else {
				ec = model.ExposureFiltered
			}
		default:
			// Declared-exposure branch: a host port published to ALL interfaces
			// that is NOT in sctx.Intended => ExposureInternet.
			// If it IS intended-public => ExposureFiltered.
			if sctx != nil && sctx.Stack != nil && declaredPublic(sctx.Stack, effectivePort) {
				if sctx.Intended != nil && sctx.Intended[effectivePort] {
					ec = model.ExposureFiltered
				} else {
					ec = model.ExposureInternet
				}
			} else {
				ec = model.ExposureUnknown
			}
		}
		if ec > best {
			best = ec
			bestEffective = effectivePort
			bestProbeOpen = probeOpen
		}
	}

	f.ExposureClass = best

	// --- Compensating controls (collapse one band each, idempotent floor) ---
	// Controls are applied against the most-exposed effective port.
	applyControls(f, sctx, bestEffective, bestProbeOpen)
}

// declaredPublic reports whether the stack declares a port published to all
// interfaces (0.0.0.0 / wildcard bind).
func declaredPublic(s *model.Stack, port int) bool {
	for _, svc := range s.Services {
		for _, pm := range svc.Ports {
			if pm.HostPort == port && pm.PublishedToAllInterfaces() {
				return true
			}
		}
	}
	return false
}

// socketFound reports whether the collector observed any socket on the port.
func socketFound(s *model.Signals, port int) bool {
	_, ok := s.SocketByPort(port)
	return ok
}

// applyControls inspects compensating controls and, for each that applies,
// appends a human Mitigations string and collapses ExposureClass one band lower.
// Controls are skipped when there is nothing to collapse (Unknown/Localhost).
// probeOpen is threaded through so controls are not applied when the probe
// already confirmed the port reachable.
func applyControls(f *model.Finding, sctx *model.ScanContext, port int, probeOpen bool) {
	if f.ExposureClass == model.ExposureUnknown || f.ExposureClass == model.ExposureLocalhost {
		return
	}

	var collector *model.Signals
	if sctx != nil {
		collector = sctx.Collector
	}

	// 1. Overlay-only reachability: every socket on the port is bound to an
	//    overlay/tailnet/loopback address and the probe did not confirm the port
	//    open from outside.
	if !probeOpen && collector != nil && overlayOnly(collector, port) {
		f.Mitigations = append(f.Mitigations,
			"Reachable only over an overlay/tailnet (WireGuard); not exposed to the public internet.")
		f.ExposureClass = prevBand(f.ExposureClass)
	}

	// 2. Authenticating reverse proxy in front of the service.
	if f.Metadata != nil && f.Metadata["auth_proxy"] == "true" {
		f.Mitigations = append(f.Mitigations,
			"Fronted by an authenticating reverse proxy; direct access requires credentials.")
		f.ExposureClass = prevBand(f.ExposureClass)
	}

	// 3. Host-firewall DROP covering the port — but only when:
	//    (a) the probe did NOT confirm the port open (a confirmed-open port is
	//        reachable regardless of inferred DROP), and
	//    (b) there is no explicit ALLOW rule for the port (which would indicate
	//        the port is intentionally permitted through the default-deny policy).
	if !probeOpen && collector != nil && firewallDrops(collector.Firewall, port) {
		f.Mitigations = append(f.Mitigations,
			"Host firewall default-inbound DROP covers this port; unsolicited inbound is blocked.")
		f.ExposureClass = prevBand(f.ExposureClass)
	}
}

// overlayOnly reports whether EVERY observed socket on the port is bound to an
// overlay/tailnet address (100.64.0.0/10) or a loopback address. A single
// routable socket (LAN/Filtered/Internet bind, e.g. 0.0.0.0/::) means the
// service is NOT overlay-only, even if an overlay socket also exists, and
// regardless of the owning process name.
func overlayOnly(s *model.Signals, port int) bool {
	found := false
	for _, sock := range s.Sockets {
		if sock.Port != port {
			continue
		}
		found = true
		c := bindClass(sock.Bind)
		// Overlay-only is a property of the BIND address, not the owning process
		// name: any routable bind disqualifies the collapse, even if a wg*-named
		// process owns it. Only overlay/loopback binds qualify.
		if c != model.ExposureOverlay && c != model.ExposureLocalhost {
			return false
		}
	}
	return found
}

// firewallDrops reports whether the host firewall would drop unsolicited inbound
// to the port without a corresponding explicit ALLOW: a default-inbound DROP/DENY
// policy where no explicit ALLOW rule matches the port, or a matching wg*-scoped
// rule. An explicit ALLOW rule for the port means the port is intentionally
// permitted and the default-deny should NOT be treated as a compensating control.
func firewallDrops(fw model.FirewallState, port int) bool {
	defaultDrop := strings.EqualFold(fw.DefaultInbound, "drop") || strings.EqualFold(fw.DefaultInbound, "deny")

	// Check for an explicit ALLOW rule on this port first. If one exists,
	// the default-deny is not a compensating control (port is intentionally open).
	// Rule format varies by backend:
	//   ufw:      "<port>/tcp ALLOW IN Anywhere"  (port token + "ALLOW" keyword)
	//   nftables: "tcp dport <port> accept"        ("dport <port>" token + "accept")
	//   pf:       "pass in ... port <port>"         ("port <port>" token + "pass")
	if ruleAllowsPort(fw, port) {
		return false
	}

	if defaultDrop {
		return true
	}

	// Check for an explicit DROP rule (wg-scoped or direct DROP) for the port.
	dportNeedle := "dport " + strconv.Itoa(port)
	for _, rule := range fw.Rules {
		if strings.Contains(rule, dportNeedle) &&
			(strings.Contains(rule, "DROP") || strings.Contains(rule, "drop") ||
				strings.Contains(rule, "wg")) {
			return true
		}
	}
	return false
}

// ruleAllowsPort reports whether any rule in fw explicitly permits inbound to
// port. Matching is done per-backend so that each parser's native rule format is
// recognised correctly:
//
//   - ufw:      "<port>/tcp ALLOW IN ..." or "<port>/udp ALLOW IN ..."
//   - nftables: "tcp dport <port> accept" or "udp dport <port> accept"
//   - pf:       "pass ... port <port>" (verbatim pass rule)
//
// For any other (or empty) backend all three patterns are tried.
//
// Each pattern is anchored so that port 22 does not match rule "2222/tcp …"
// or "tcp dport 2222 …" or "port 2222" via substring collision.
func ruleAllowsPort(fw model.FirewallState, port int) bool {
	portStr := strconv.Itoa(port)
	backend := strings.ToLower(fw.Backend)

	// ufwPortMatch returns true when rule contains the anchored token "<port>/proto".
	// UFW rows look like "443/tcp                    ALLOW IN    Anywhere".
	// The port token is at the start of the row or preceded by whitespace;
	// we check for " <port>/" OR that the trimmed rule starts with "<port>/".
	ufwPortMatch := func(rule string) bool {
		for _, proto := range []string{"/tcp", "/udp"} {
			needle := portStr + proto
			trimmed := strings.TrimSpace(rule)
			if strings.HasPrefix(trimmed, needle) {
				return true
			}
			// Also match when a space precedes the port token (e.g. multi-column output).
			if strings.Contains(rule, " "+needle) {
				return true
			}
		}
		return false
	}

	// nftPortMatch returns true when rule contains "dport <port>" followed
	// immediately by a space or tab (or end-of-string), preventing "dport 22"
	// from matching "dport 2222".
	nftPortMatch := func(rule string) bool {
		needle := "dport " + portStr
		idx := strings.Index(rule, needle)
		if idx < 0 {
			return false
		}
		after := idx + len(needle)
		if after >= len(rule) {
			return true // needle is at end of string
		}
		ch := rule[after]
		return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
	}

	// pfPortMatch returns true when rule contains "port <port>" followed
	// immediately by a space, tab, or end-of-string.
	pfPortMatch := func(rule string) bool {
		needle := "port " + portStr
		idx := strings.Index(rule, needle)
		if idx < 0 {
			return false
		}
		after := idx + len(needle)
		if after >= len(rule) {
			return true
		}
		ch := rule[after]
		return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
	}

	for _, rule := range fw.Rules {
		switch backend {
		case "ufw":
			// UFW table rows: "<port>/tcp  ALLOW IN  Anywhere"
			if ufwPortMatch(rule) && strings.Contains(strings.ToUpper(rule), "ALLOW") {
				return true
			}
		case "nftables":
			// nftables rules: "tcp dport <port> accept"
			if nftPortMatch(rule) && strings.Contains(strings.ToLower(rule), "accept") {
				return true
			}
		case "pf":
			// pf rules: "pass in proto tcp from any to any port <port>"
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rule)), "pass") &&
				pfPortMatch(rule) {
				return true
			}
		default:
			// Unknown backend: try all three patterns.
			upper := strings.ToUpper(rule)
			lower := strings.ToLower(rule)
			if ufwPortMatch(rule) && strings.Contains(upper, "ALLOW") {
				return true
			}
			if nftPortMatch(rule) && strings.Contains(lower, "accept") {
				return true
			}
			if strings.HasPrefix(strings.TrimSpace(lower), "pass") && pfPortMatch(rule) {
				return true
			}
		}
	}
	return false
}
