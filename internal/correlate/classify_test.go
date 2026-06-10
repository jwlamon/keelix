package correlate

import (
	"strconv"
	"strings"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/aiagent" // registers AGT001–AGT010
	"github.com/jakelamon/keelix/internal/model"
)

func TestPrevBand(t *testing.T) {
	tests := []struct {
		in   model.ExposureClass
		want model.ExposureClass
	}{
		{model.ExposureInternet, model.ExposureFiltered},
		{model.ExposureFiltered, model.ExposureLAN},
		{model.ExposureLAN, model.ExposureOverlay},
		{model.ExposureOverlay, model.ExposureLocalhost},
		{model.ExposureLocalhost, model.ExposureLocalhost}, // floor
		{model.ExposureUnknown, model.ExposureUnknown},     // unknown has no lower band
	}
	for _, tt := range tests {
		if got := prevBand(tt.in); got != tt.want {
			t.Fatalf("prevBand(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestBindClass(t *testing.T) {
	tests := []struct {
		bind string
		want model.ExposureClass
	}{
		{"127.0.0.1", model.ExposureLocalhost},
		{"::1", model.ExposureLocalhost},
		{"100.64.0.1", model.ExposureOverlay}, // CGNAT / tailnet
		{"10.0.0.5", model.ExposureLAN},       // RFC1918
		{"192.168.1.10", model.ExposureLAN},   // RFC1918
		{"172.16.0.9", model.ExposureLAN},     // RFC1918
		{"0.0.0.0", model.ExposureInternet},   // wildcard
		{"::", model.ExposureInternet},        // wildcard v6
		{"", model.ExposureUnknown},
		{"203.0.113.7", model.ExposureInternet}, // public IP literal binds wide
		// Fix (d): link-local => LAN
		{"169.254.1.1", model.ExposureLAN}, // IPv4 link-local
		{"fe80::1", model.ExposureLAN},     // IPv6 link-local
	}
	for _, tt := range tests {
		if got := bindClass(tt.bind); got != tt.want {
			t.Fatalf("bindClass(%q) = %v, want %v", tt.bind, got, tt.want)
		}
	}
}

func TestFindingPort(t *testing.T) {
	tests := []struct {
		name     string
		finding  model.Finding
		wantPort int
		wantOK   bool
	}{
		{
			name:     "from metadata",
			finding:  model.Finding{Metadata: map[string]string{"port": "5432"}},
			wantPort: 5432,
			wantOK:   true,
		},
		{
			name:     "metadata wins over resource",
			finding:  model.Finding{Metadata: map[string]string{"port": "5432"}, Resource: "port 443"},
			wantPort: 5432,
			wantOK:   true,
		},
		{
			name:     "from resource fallback",
			finding:  model.Finding{Resource: "port 443"},
			wantPort: 443,
			wantOK:   true,
		},
		{
			name:     "no port anywhere",
			finding:  model.Finding{Resource: "container app"},
			wantPort: 0,
			wantOK:   false,
		},
		{
			name:     "empty metadata value falls through to resource",
			finding:  model.Finding{Metadata: map[string]string{"port": ""}, Resource: "port 6379"},
			wantPort: 6379,
			wantOK:   true,
		},
		{
			name:     "non-numeric metadata falls through to resource",
			finding:  model.Finding{Metadata: map[string]string{"port": "nope"}, Resource: "port 8080"},
			wantPort: 8080,
			wantOK:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPort, gotOK := findingPort(tt.finding)
			if gotPort != tt.wantPort || gotOK != tt.wantOK {
				t.Fatalf("findingPort() = (%d, %v), want (%d, %v)", gotPort, gotOK, tt.wantPort, tt.wantOK)
			}
		})
	}
}

// fctx builds a ScanContext with the given collector and probe (either nil).
func fctx(col *model.Signals, probe *model.ProbeResult) *model.ScanContext {
	return &model.ScanContext{Collector: col, Probe: probe}
}

func sigWith(sockets ...model.ListeningSocket) *model.Signals {
	return &model.Signals{Sockets: sockets}
}

func portFinding(port int) model.Finding {
	return model.Finding{
		CheckID:  "EXP001",
		Group:    model.GroupExposure,
		Severity: model.SeverityCritical,
		Resource: "port " + strconvI(port),
		Metadata: map[string]string{"port": strconvI(port)},
	}
}

func strconvI(n int) string { return strconv.Itoa(n) }

func TestClassify_BaseFromSocketAndProbe(t *testing.T) {
	tests := []struct {
		name    string
		finding model.Finding
		sctx    *model.ScanContext
		want    model.ExposureClass
	}{
		{
			name:    "0.0.0.0 bind + probe open => Internet",
			finding: portFinding(5432),
			sctx: fctx(
				sigWith(model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 5432}),
				&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
			),
			want: model.ExposureInternet,
		},
		{
			name:    "0.0.0.0 bind + probe filtered => Filtered",
			finding: portFinding(5432),
			sctx: fctx(
				sigWith(model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 5432}),
				&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: false}}},
			),
			want: model.ExposureFiltered,
		},
		{
			name:    "127.0.0.1 bind => Localhost regardless of probe",
			finding: portFinding(5432),
			sctx: fctx(
				sigWith(model.ListeningSocket{Proto: "tcp", Bind: "127.0.0.1", Port: 5432}),
				&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
			),
			want: model.ExposureLocalhost,
		},
		{
			// After D.4: overlay-only control collapses Overlay → Localhost.
			name:    "100.x bind => Localhost (overlay control collapses)",
			finding: portFinding(5432),
			sctx: fctx(
				sigWith(model.ListeningSocket{Proto: "tcp", Bind: "100.64.0.3", Port: 5432}),
				nil,
			),
			want: model.ExposureLocalhost,
		},
		{
			name:    "nil collector falls back to probe open => Internet",
			finding: portFinding(5432),
			sctx: fctx(nil,
				&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
			),
			want: model.ExposureInternet,
		},
		{
			name:    "nil collector + probe closed => Filtered",
			finding: portFinding(5432),
			sctx: fctx(nil,
				&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: false}}},
			),
			want: model.ExposureFiltered,
		},
		{
			name:    "no socket, no probe, has port => Unknown",
			finding: portFinding(5432),
			sctx:    fctx(nil, nil),
			want:    model.ExposureUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []model.Finding{tt.finding}
			Classify(findings, tt.sctx)
			if findings[0].ExposureClass != tt.want {
				t.Fatalf("ExposureClass = %v, want %v", findings[0].ExposureClass, tt.want)
			}
		})
	}
}

func TestClassify_PassingFindingUntouched(t *testing.T) {
	f := model.Finding{CheckID: "EXP001", Severity: model.SeverityOK, Passed: true,
		Resource: "port 5432", Metadata: map[string]string{"port": "5432"}}
	findings := []model.Finding{f}
	Classify(findings, fctx(
		sigWith(model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 5432}),
		&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
	))
	if findings[0].ExposureClass != model.ExposureUnknown {
		t.Fatalf("passing finding mutated: ExposureClass = %v, want %v (zero)", findings[0].ExposureClass, model.ExposureUnknown)
	}
	if len(findings[0].Mitigations) != 0 {
		t.Fatalf("passing finding gained mitigations: %v", findings[0].Mitigations)
	}
}

func hasMitigation(ms []string, substr string) bool {
	for _, m := range ms {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func TestClassify_CompensatingControls(t *testing.T) {
	t.Run("overlay iface collapses Internet->Filtered with mitigation", func(t *testing.T) {
		// Bind is wildcard + probe open (=> Internet), but a wg* iface socket
		// also serves the port: overlay-only reachability collapses one band.
		f := portFinding(5432)
		sctx := fctx(
			&model.Signals{Sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "100.64.0.4", Port: 5432, Comm: "postgres"},
			}},
			nil,
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		// 100.x base is Overlay; overlay-only mitigation collapses to Localhost.
		if findings[0].ExposureClass != model.ExposureLocalhost {
			t.Fatalf("ExposureClass = %v, want Localhost", findings[0].ExposureClass)
		}
		if !hasMitigation(findings[0].Mitigations, "overlay") {
			t.Fatalf("missing overlay mitigation: %v", findings[0].Mitigations)
		}
	})

	t.Run("wg-named process on a public bind is NOT overlay-only", func(t *testing.T) {
		// A wireguard-named process serving the port on a PUBLIC 0.0.0.0 bind must
		// not be treated as overlay-only: a routable bind disqualifies the collapse
		// regardless of the owning process name. Without a probe, base is Internet
		// downgraded to Filtered; the overlay control must NOT fire.
		f := portFinding(6379)
		sctx := fctx(
			&model.Signals{Sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "0.0.0.0", Port: 6379, Comm: "wg0"},
			}},
			nil,
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureFiltered {
			t.Fatalf("ExposureClass = %v, want Filtered (public bind, no overlay collapse)", findings[0].ExposureClass)
		}
		if hasMitigation(findings[0].Mitigations, "overlay") {
			t.Fatalf("overlay mitigation wrongly applied to a public bind: %v", findings[0].Mitigations)
		}
	})

	t.Run("auth proxy collapses Internet->Filtered", func(t *testing.T) {
		f := portFinding(443)
		f.Metadata["auth_proxy"] = "true"
		sctx := fctx(
			sigWith(model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 443}),
			&model.ProbeResult{Reachable: map[int]model.PortProbe{443: {Port: 443, Open: true}}},
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureFiltered {
			t.Fatalf("ExposureClass = %v, want Filtered", findings[0].ExposureClass)
		}
		if !hasMitigation(findings[0].Mitigations, "reverse proxy") {
			t.Fatalf("missing reverse-proxy mitigation: %v", findings[0].Mitigations)
		}
	})

	// Fix (c): firewall default-deny does NOT collapse when probeOpen==true
	// (a confirmed-open port is reachable regardless of inferred DROP).
	// Updated from stale expectation: was Filtered, now Internet (probe wins).
	t.Run("firewall DROP does NOT collapse when probe confirms open", func(t *testing.T) {
		f := portFinding(5432)
		sctx := fctx(
			&model.Signals{
				Sockets:  []model.ListeningSocket{{Proto: "tcp", Bind: "0.0.0.0", Port: 5432}},
				Firewall: model.FirewallState{Backend: "ufw", DefaultInbound: "drop"},
			},
			&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		// probeOpen=true overrides default-deny: port IS reachable, stay Internet.
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("ExposureClass = %v, want Internet (probe-confirmed open beats inferred DROP)", findings[0].ExposureClass)
		}
	})

	// Fix (c): firewall default-deny DOES collapse when probe is absent/closed.
	// Base class: 0.0.0.0 + !probeOpen => Filtered.
	// Firewall default-deny (no explicit ALLOW) collapses Filtered -> LAN.
	t.Run("firewall DROP collapses Filtered->LAN when probe absent and no ALLOW", func(t *testing.T) {
		f := portFinding(5432)
		sctx := fctx(
			&model.Signals{
				Sockets:  []model.ListeningSocket{{Proto: "tcp", Bind: "0.0.0.0", Port: 5432}},
				Firewall: model.FirewallState{Backend: "ufw", DefaultInbound: "drop"},
			},
			nil,
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureLAN {
			t.Fatalf("ExposureClass = %v, want LAN (Filtered base collapsed by default-deny)", findings[0].ExposureClass)
		}
		if !hasMitigation(findings[0].Mitigations, "firewall") {
			t.Fatalf("missing firewall mitigation: %v", findings[0].Mitigations)
		}
	})

	// Fix (b): overlay+public mix on one port => NOT collapsed (public socket present).
	// Updated from stale expectation: was Filtered, now Internet (probeOpen + public socket).
	t.Run("0.0.0.0 bind but tailnet-only does NOT collapse when probe open and public socket present", func(t *testing.T) {
		f := portFinding(6379)
		sctx := fctx(
			&model.Signals{Sockets: []model.ListeningSocket{
				{Proto: "tcp", Bind: "0.0.0.0", Port: 6379, Comm: "redis"},
				{Proto: "tcp", Bind: "100.64.0.9", Port: 6379, Comm: "redis"},
			},
				Firewall: FirewallStateNone()},
			&model.ProbeResult{Reachable: map[int]model.PortProbe{6379: {Port: 6379, Open: true}}},
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		// max socket class = Internet (from 0.0.0.0); probeOpen => no Internet->Filtered downgrade;
		// overlayOnly=false (public socket present) => no collapse; probeOpen => no FW collapse.
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("ExposureClass = %v, want Internet (public socket + probe open, overlay NOT sole path)", findings[0].ExposureClass)
		}
	})
}

// TestClassify_FIX4 contains the new table-driven tests required by FIX-4.
func TestClassify_FIX4(t *testing.T) {
	t.Run("dual-bind loopback+wildcard probe-open => Internet", func(t *testing.T) {
		// Fix (a): max over sockets. 0.0.0.0 => Internet, 127.0.0.1 => Localhost.
		// Max = Internet. probeOpen=true => no downgrade. Result: Internet.
		f := portFinding(5432)
		sctx := fctx(
			sigWith(
				model.ListeningSocket{Proto: "tcp", Bind: "127.0.0.1", Port: 5432},
				model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 5432},
			),
			&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("ExposureClass = %v, want Internet (dual-bind, probe open)", findings[0].ExposureClass)
		}
	})

	t.Run("default-deny WITH explicit ALLOW for port + probe-open => stays Internet (UFW format)", func(t *testing.T) {
		// Fix (c): explicit ALLOW rule overrides default-deny; plus probeOpen=true.
		// Uses the real UFW rule format emitted by parseUFW: "443/tcp ALLOW IN Anywhere".
		f := portFinding(443)
		sctx := fctx(
			&model.Signals{
				Sockets: []model.ListeningSocket{{Proto: "tcp", Bind: "0.0.0.0", Port: 443}},
				Firewall: model.FirewallState{
					Backend:        "ufw",
					DefaultInbound: "drop",
					Rules:          []string{"443/tcp                    ALLOW IN    Anywhere"},
				},
			},
			&model.ProbeResult{Reachable: map[int]model.PortProbe{443: {Port: 443, Open: true}}},
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("ExposureClass = %v, want Internet (explicit ALLOW + probeOpen)", findings[0].ExposureClass)
		}
	})

	t.Run("default-deny WITH explicit ALLOW for port, no probe => stays Filtered (UFW format)", func(t *testing.T) {
		// Fix (c): explicit ALLOW in rules means port is intentionally open; don't collapse.
		// Uses the real UFW rule format emitted by parseUFW: "443/tcp ALLOW IN Anywhere".
		f := portFinding(443)
		sctx := fctx(
			&model.Signals{
				Sockets: []model.ListeningSocket{{Proto: "tcp", Bind: "0.0.0.0", Port: 443}},
				Firewall: model.FirewallState{
					Backend:        "ufw",
					DefaultInbound: "drop",
					Rules:          []string{"443/tcp                    ALLOW IN    Anywhere"},
				},
			},
			nil,
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		// Explicit ALLOW overrides default-deny collapse.
		if findings[0].ExposureClass != model.ExposureFiltered {
			// base class is Filtered (Internet && !probeOpen => Filtered); no collapse since ALLOW exists
			t.Fatalf("ExposureClass = %v, want Filtered (ALLOW overrides default-deny, no collapse)", findings[0].ExposureClass)
		}
	})

	t.Run("default-deny WITH explicit ALLOW for port, no probe => stays Filtered (nftables format)", func(t *testing.T) {
		// Fix (c): explicit accept rule in nftables means port is intentionally open; don't collapse.
		// Uses the real nftables rule format emitted by parseNft: "tcp dport 22 accept".
		f := portFinding(22)
		sctx := fctx(
			&model.Signals{
				Sockets: []model.ListeningSocket{{Proto: "tcp", Bind: "0.0.0.0", Port: 22}},
				Firewall: model.FirewallState{
					Backend:        "nftables",
					DefaultInbound: "drop",
					Rules:          []string{"tcp dport 22 accept"},
				},
			},
			nil,
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		// Explicit accept overrides default-deny collapse.
		if findings[0].ExposureClass != model.ExposureFiltered {
			// base class is Filtered (Internet && !probeOpen => Filtered); no collapse since accept exists
			t.Fatalf("ExposureClass = %v, want Filtered (nftables accept overrides default-deny, no collapse)", findings[0].ExposureClass)
		}
	})

	t.Run("overlay+public mix on one port => NOT collapsed", func(t *testing.T) {
		// Fix (b): overlayOnly is FORALL; one public socket means NOT overlay-only.
		f := portFinding(8080)
		sctx := fctx(
			sigWith(
				model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 8080},
				model.ListeningSocket{Proto: "tcp", Bind: "100.64.0.1", Port: 8080},
			),
			&model.ProbeResult{Reachable: map[int]model.PortProbe{8080: {Port: 8080, Open: true}}},
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		// max class Internet (0.0.0.0), probe open => Internet base, no overlay collapse.
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("ExposureClass = %v, want Internet (public socket in mix, not overlay-only)", findings[0].ExposureClass)
		}
	})

	t.Run("link-local bind => LAN", func(t *testing.T) {
		// Fix (d): 169.254.x.x is LAN, not Internet.
		f := portFinding(8080)
		sctx := fctx(
			sigWith(model.ListeningSocket{Proto: "tcp", Bind: "169.254.1.1", Port: 8080}),
			nil,
		)
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureLAN {
			t.Fatalf("ExposureClass = %v, want LAN (link-local bind)", findings[0].ExposureClass)
		}
	})

	t.Run("declared 0.0.0.0 sensitive port, no probe/collector, not intended => Internet", func(t *testing.T) {
		// Fix (e): declared-exposure branch. Port published to all interfaces,
		// not in intended set => treat as Internet (intent says public, unmitigated).
		f := portFinding(5432)
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "db",
					Image: "postgres:16",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack:     stack,
			Probe:     nil,
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("ExposureClass = %v, want Internet (declared public, not intended)", findings[0].ExposureClass)
		}
	})

	t.Run("declared 0.0.0.0 port, no probe/collector, intended-public => Filtered", func(t *testing.T) {
		// Fix (e): declared-exposure branch. Port published to all interfaces,
		// IS in intended set => ExposureFiltered (intended public = lower urgency).
		f := portFinding(443)
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "web",
					Image: "nginx:latest",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 443, ContainerPort: 443, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack:     stack,
			Probe:     nil,
			Collector: nil,
			Intended:  map[int]bool{443: true},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureFiltered {
			t.Fatalf("ExposureClass = %v, want Filtered (declared public, intended)", findings[0].ExposureClass)
		}
	})
}

func FirewallStateNone() model.FirewallState { return model.FirewallState{Backend: "none"} }

// TestHostPortFor verifies the hostPortFor helper returns the mapped host port
// for a container port, or 0 when unmapped/ambiguous.
func TestHostPortFor(t *testing.T) {
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "sonarr",
				Image: "linuxserver/sonarr",
				Ports: []model.PortMapping{
					// Asymmetric: host 18989 → container 8989
					{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
				},
			},
			{
				Name:  "radarr",
				Image: "linuxserver/radarr",
				Ports: []model.PortMapping{
					// Symmetric: host 7878 → container 7878
					{HostIP: "0.0.0.0", HostPort: 7878, ContainerPort: 7878, Protocol: "tcp"},
				},
			},
		},
	}

	tests := []struct {
		name          string
		containerPort int
		wantHostPort  int
	}{
		{"asymmetric publish 18989:8989", 8989, 18989},
		{"symmetric publish 7878:7878", 7878, 7878},
		{"unmapped container port", 9696, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostPortFor(stack, tt.containerPort)
			if got != tt.wantHostPort {
				t.Fatalf("hostPortFor(containerPort=%d) = %d, want %d", tt.containerPort, got, tt.wantHostPort)
			}
		})
	}
}

// TestClassify_AsymmetricPublish is the R2-3 regression test.
// A SVC finding on container port 8989 with an asymmetric publish 18989:8989
// must classify as ExposureInternet when the declared host port 18989 is
// reachable from outside. Before the fix, classifyOne matched on 8989 which
// was never in the declared/probe map, yielding ExposureUnknown.
func TestClassify_AsymmetricPublish(t *testing.T) {
	t.Run("asymmetric publish classifies Internet via declared host port", func(t *testing.T) {
		// SVC finding: container port 8989 (Sonarr default)
		f := model.Finding{
			CheckID:  "SVC010",
			Group:    model.GroupService,
			Severity: model.SeverityCritical,
			Metadata: map[string]string{"port": "8989"},
		}
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "sonarr",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						// Asymmetric: host 18989 → container 8989
						{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack:     stack,
			Probe:     nil, // no probe
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("R2-3: ExposureClass = %v, want Internet (asymmetric publish 18989:8989, host port declared public)", findings[0].ExposureClass)
		}
	})

	t.Run("asymmetric publish classifies Internet when probe confirms host port open", func(t *testing.T) {
		f := model.Finding{
			CheckID:  "SVC010",
			Group:    model.GroupService,
			Severity: model.SeverityCritical,
			Metadata: map[string]string{"port": "8989"},
		}
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "sonarr",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack: stack,
			// Probe sees host port 18989 open (not 8989)
			Probe: &model.ProbeResult{
				Reachable: map[int]model.PortProbe{18989: {Port: 18989, Open: true}},
			},
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("R2-3: ExposureClass = %v, want Internet (probe confirmed host port 18989 open)", findings[0].ExposureClass)
		}
	})

	t.Run("unpublished container port stays Unknown", func(t *testing.T) {
		// Container-internal port with no host publish: must stay ExposureUnknown.
		f := model.Finding{
			CheckID:  "SVC010",
			Group:    model.GroupService,
			Severity: model.SeverityCritical,
			Metadata: map[string]string{"port": "8989"},
		}
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "sonarr",
					Image: "linuxserver/sonarr",
					// No port publish
					Ports: []model.PortMapping{},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack:     stack,
			Probe:     nil,
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureUnknown {
			t.Fatalf("R2-3: unpublished port ExposureClass = %v, want Unknown", findings[0].ExposureClass)
		}
	})
}

// TestHostPortsFor verifies hostPortsFor returns all mapped host ports for a
// container port — including the ambiguous case where multiple services publish
// the same container port (R3-3 fix).
func TestHostPortsFor(t *testing.T) {
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "sonarr",
				Image: "linuxserver/sonarr",
				Ports: []model.PortMapping{
					// Asymmetric: host 18989 → container 8989
					{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
				},
			},
			{
				Name:  "sonarr2",
				Image: "linuxserver/sonarr",
				Ports: []model.PortMapping{
					// Second service also publishing container 8989 on a different host port
					{HostIP: "0.0.0.0", HostPort: 28989, ContainerPort: 8989, Protocol: "tcp"},
				},
			},
			{
				Name:  "radarr",
				Image: "linuxserver/radarr",
				Ports: []model.PortMapping{
					// Symmetric: host 7878 → container 7878
					{HostIP: "0.0.0.0", HostPort: 7878, ContainerPort: 7878, Protocol: "tcp"},
				},
			},
		},
	}

	tests := []struct {
		name          string
		containerPort int
		wantLen       int
		wantPorts     []int
	}{
		{
			name:          "single mapping returns one port",
			containerPort: 7878,
			wantLen:       1,
			wantPorts:     []int{7878},
		},
		{
			name:          "ambiguous: two services share container port 8989 → both host ports returned",
			containerPort: 8989,
			wantLen:       2,
			wantPorts:     []int{18989, 28989},
		},
		{
			name:          "unmapped container port returns empty",
			containerPort: 9696,
			wantLen:       0,
			wantPorts:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostPortsFor(stack, tt.containerPort)
			if len(got) != tt.wantLen {
				t.Fatalf("hostPortsFor(containerPort=%d) len=%d, want %d; got %v",
					tt.containerPort, len(got), tt.wantLen, got)
			}
			portSet := make(map[int]bool, len(got))
			for _, p := range got {
				portSet[p] = true
			}
			for _, want := range tt.wantPorts {
				if !portSet[want] {
					t.Fatalf("hostPortsFor(containerPort=%d) missing port %d in result %v",
						tt.containerPort, want, got)
				}
			}
		})
	}
}

// TestClassify_R3_3_AmbiguousHostPort is the R3-3 regression test.
// When two services both publish the same container port (ambiguous), classifyOne
// must union over all mapped host ports and pick the most-exposed class rather
// than falling back to the container port and getting ExposureUnknown.
func TestClassify_R3_3_AmbiguousHostPort(t *testing.T) {
	t.Run("ambiguous publish: two services sharing container port, one host port declared public => Internet", func(t *testing.T) {
		// SVC finding on container port 8989.
		// Two services map container 8989 → host 18989 and host 28989.
		// Both host ports are published to 0.0.0.0 → should classify as Internet.
		f := model.Finding{
			CheckID:  "SVC010",
			Group:    model.GroupService,
			Severity: model.SeverityCritical,
			Metadata: map[string]string{"port": "8989"},
		}
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "sonarr-a",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
				{
					Name:  "sonarr-b",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 28989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack:     stack,
			Probe:     nil,
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("R3-3: ambiguous publish ExposureClass = %v, want Internet (both host ports declared public on 0.0.0.0)", findings[0].ExposureClass)
		}
	})

	t.Run("ambiguous publish: probe confirms one host port open => Internet", func(t *testing.T) {
		f := model.Finding{
			CheckID:  "SVC010",
			Group:    model.GroupService,
			Severity: model.SeverityCritical,
			Metadata: map[string]string{"port": "8989"},
		}
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "sonarr-a",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
				{
					Name:  "sonarr-b",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 28989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack: stack,
			// Probe sees host port 18989 open
			Probe: &model.ProbeResult{
				Reachable: map[int]model.PortProbe{18989: {Port: 18989, Open: true}},
			},
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("R3-3: ambiguous publish with probe on one host port ExposureClass = %v, want Internet", findings[0].ExposureClass)
		}
	})

	t.Run("single unambiguous publish still works (regression guard)", func(t *testing.T) {
		f := model.Finding{
			CheckID:  "SVC010",
			Group:    model.GroupService,
			Severity: model.SeverityCritical,
			Metadata: map[string]string{"port": "8989"},
		}
		stack := &model.Stack{
			Services: []*model.Service{
				{
					Name:  "sonarr",
					Image: "linuxserver/sonarr",
					Ports: []model.PortMapping{
						{HostIP: "0.0.0.0", HostPort: 18989, ContainerPort: 8989, Protocol: "tcp"},
					},
				},
			},
		}
		sctx := &model.ScanContext{
			Stack:     stack,
			Probe:     nil,
			Collector: nil,
			Intended:  map[int]bool{},
		}
		findings := []model.Finding{f}
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("R3-3 regression: single asymmetric publish ExposureClass = %v, want Internet", findings[0].ExposureClass)
		}
	})
}

// findRegisteredCheckCorrelate looks up a registered check by ID.
func findRegisteredCheckCorrelate(t *testing.T, id string) model.Check {
	t.Helper()
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %s not registered (blank-import missing?)", id)
	return nil
}

// TestRFX7_AIMCPExposureClassPreserved is the PARSER-FED regression test for
// RFX-7. It runs the real AGT001 check (registered via blank-import) over a
// ScanContext whose ConfigFact.Values carry exactly the keys that the real
// parseOpenclawConfig collector pipeline produces for an openclaw-config with
// tools.exec.ask=off. The check deliberately sets ExposureLocalhost in-check;
// Classify must not overwrite it with ExposureUnknown.
//
// Two sub-tests:
//  1. AGT001 finding (DomainAIMCP, no port) retains ExposureLocalhost after Classify.
//  2. A box (GroupExposure) finding with a port is still classified normally.
func TestRFX7_AIMCPExposureClassPreserved(t *testing.T) {
	t.Run("AGT001 ExposureLocalhost set in-check is NOT clobbered by Classify", func(t *testing.T) {
		// Values match what the real parseOpenclawConfig collector pipeline emits
		// for an openclaw.json with {"tools":{"exec":{"ask":"off",...},...},...}.
		// Using the real registered AGT001 check (not a synthetic Finding) ensures
		// that the ExposureLocalhost originates from the check's own logic, exactly
		// as it would in production — this is the parser-fed pipeline path.
		c := findRegisteredCheckCorrelate(t, "AGT001")
		sigs := &model.Signals{
			Configs: []model.ConfigFact{
				{
					SchemaID:    "openclaw-config",
					SchemaKnown: true,
					// Values are the exact flat keys emitted by parseOpenclawConfig:
					// flattenJSON({"tools":{"exec":{"ask":"off","security":"strict"},...}})
					// plus the required keys the parser always emits.
					Values: map[string]string{
						"tools.exec.ask":               "off",
						"tools.exec.security":          "strict",
						"tools.fs.workspaceOnly":       "true",
						"agents.defaults.sandbox.mode": "docker",
						"browser.enabled":              "false",
						"tools.web.search.provider":    "brave",
						"channels.discord.groupPolicy": "allowlist",
						"channels.telegram.dmPolicy":   "allowlist",
					},
				},
			},
		}
		ctx := &model.ScanContext{Collector: sigs}
		findings := c.Run(ctx)

		// AGT001 must emit a failing finding with ExposureLocalhost set in-check.
		var agt001Finding *model.Finding
		for i := range findings {
			if findings[i].CheckID == "AGT001" && findings[i].IsFail() {
				agt001Finding = &findings[i]
				break
			}
		}
		if agt001Finding == nil {
			t.Fatalf("RFX-7: AGT001 must fire for tools.exec.ask=off; got %+v", findings)
		}
		if agt001Finding.ExposureClass != model.ExposureLocalhost {
			t.Fatalf("RFX-7 pre-condition: AGT001 in-check ExposureClass = %v, want Localhost (check must set it)", agt001Finding.ExposureClass)
		}

		// Run Classify — before the fix this clobbers ExposureLocalhost with
		// ExposureUnknown because the finding has no port number.
		Classify(findings, nil)

		for i := range findings {
			if findings[i].CheckID == "AGT001" && findings[i].IsFail() {
				if findings[i].ExposureClass != model.ExposureLocalhost {
					t.Fatalf("RFX-7: Classify clobbered AGT001 ExposureClass: got %v, want Localhost (5x numeric inflation bug)", findings[i].ExposureClass)
				}
				return
			}
		}
		t.Fatal("RFX-7: AGT001 failing finding disappeared after Classify")
	})

	t.Run("box finding (GroupExposure, has port) is still classified by Classify", func(t *testing.T) {
		// Regression guard: skipping DomainAIMCP must not affect GroupExposure findings.
		f := portFinding(5432)
		findings := []model.Finding{f}
		sctx := fctx(
			sigWith(model.ListeningSocket{Proto: "tcp", Bind: "0.0.0.0", Port: 5432}),
			&model.ProbeResult{Reachable: map[int]model.PortProbe{5432: {Port: 5432, Open: true}}},
		)
		Classify(findings, sctx)
		if findings[0].ExposureClass != model.ExposureInternet {
			t.Fatalf("box finding ExposureClass = %v, want Internet (Classify must still run for box domain)", findings[0].ExposureClass)
		}
	})
}

// TestClassify_SelfSetExposureClassPreserved verifies that Classify does not
// overwrite a finding whose ExposureClass was already set in-check (non-Unknown),
// even when the finding is not in the DomainAIMCP domain. This allows HST003 and
// future checks to self-classify and have that class respected by the correlator.
func TestClassify_SelfSetExposureClassPreserved(t *testing.T) {
	// GroupHost (non-AIMCP domain) finding with ExposureLAN pre-set in-check.
	// Classify must leave ExposureLAN untouched (not run classifyOne on it).
	f := model.Finding{
		CheckID:       "HST003",
		Group:         model.GroupHost,
		Severity:      model.SeverityCritical,
		ExposureClass: model.ExposureLAN,
		// No port metadata: if classifyOne ran it would set ExposureUnknown.
	}
	findings := []model.Finding{f}
	Classify(findings, nil)
	if findings[0].ExposureClass != model.ExposureLAN {
		t.Fatalf("Classify overwrote self-set ExposureClass: got %v, want ExposureLAN", findings[0].ExposureClass)
	}
}

// TestRuleAllowsPort is a dedicated table test that verifies anchored matching
// prevents substring collisions (e.g. port 22 must not match a rule for 2222).
func TestRuleAllowsPort(t *testing.T) {
	tests := []struct {
		name string
		fw   model.FirewallState
		port int
		want bool
	}{
		// --- UFW: exact-port matches ---
		{
			name: "ufw: exact match 443/tcp",
			fw: model.FirewallState{
				Backend: "ufw",
				Rules:   []string{"443/tcp                    ALLOW IN    Anywhere"},
			},
			port: 443,
			want: true,
		},
		{
			name: "ufw: exact match 22/tcp",
			fw: model.FirewallState{
				Backend: "ufw",
				Rules:   []string{"22/tcp                     ALLOW IN    Anywhere"},
			},
			port: 22,
			want: true,
		},
		// --- UFW: substring collision must NOT match ---
		{
			name: "ufw: port 22 must NOT match rule for 2222/tcp",
			fw: model.FirewallState{
				Backend: "ufw",
				Rules:   []string{"2222/tcp                   ALLOW IN    Anywhere"},
			},
			port: 22,
			want: false,
		},
		{
			name: "ufw: port 443 must NOT match rule for 1443/tcp",
			fw: model.FirewallState{
				Backend: "ufw",
				Rules:   []string{"1443/tcp                   ALLOW IN    Anywhere"},
			},
			port: 443,
			want: false,
		},
		{
			name: "ufw: port 8 must NOT match rule for 80/tcp",
			fw: model.FirewallState{
				Backend: "ufw",
				Rules:   []string{"80/tcp                     ALLOW IN    Anywhere"},
			},
			port: 8,
			want: false,
		},
		// --- nftables: exact-port matches ---
		{
			name: "nftables: exact match dport 22",
			fw: model.FirewallState{
				Backend: "nftables",
				Rules:   []string{"tcp dport 22 accept"},
			},
			port: 22,
			want: true,
		},
		{
			name: "nftables: exact match dport 443",
			fw: model.FirewallState{
				Backend: "nftables",
				Rules:   []string{"tcp dport 443 accept"},
			},
			port: 443,
			want: true,
		},
		// --- nftables: substring collision must NOT match ---
		{
			name: "nftables: port 22 must NOT match dport 2222",
			fw: model.FirewallState{
				Backend: "nftables",
				Rules:   []string{"tcp dport 2222 accept"},
			},
			port: 22,
			want: false,
		},
		{
			name: "nftables: port 443 must NOT match dport 4430",
			fw: model.FirewallState{
				Backend: "nftables",
				Rules:   []string{"tcp dport 4430 accept"},
			},
			port: 443,
			want: false,
		},
		// --- pf: exact-port matches ---
		{
			name: "pf: exact match port 22",
			fw: model.FirewallState{
				Backend: "pf",
				Rules:   []string{"pass in proto tcp from any to any port 22"},
			},
			port: 22,
			want: true,
		},
		{
			name: "pf: exact match port 443 end-of-string",
			fw: model.FirewallState{
				Backend: "pf",
				Rules:   []string{"pass in proto tcp from any to any port 443"},
			},
			port: 443,
			want: true,
		},
		// --- pf: substring collision must NOT match ---
		{
			name: "pf: port 22 must NOT match port 2222",
			fw: model.FirewallState{
				Backend: "pf",
				Rules:   []string{"pass in proto tcp from any to any port 2222"},
			},
			port: 22,
			want: false,
		},
		{
			name: "pf: port 443 must NOT match port 4430",
			fw: model.FirewallState{
				Backend: "pf",
				Rules:   []string{"pass in proto tcp from any to any port 4430"},
			},
			port: 443,
			want: false,
		},
		// --- no rules => never matches ---
		{
			name: "ufw: empty rules => false",
			fw:   model.FirewallState{Backend: "ufw", Rules: []string{}},
			port: 22,
			want: false,
		},
		// --- default backend (unknown) also anchors correctly ---
		{
			name: "unknown backend: exact ufw-style match",
			fw: model.FirewallState{
				Backend: "other",
				Rules:   []string{"22/tcp ALLOW IN Anywhere"},
			},
			port: 22,
			want: true,
		},
		{
			name: "unknown backend: port 22 must NOT match 2222/tcp",
			fw: model.FirewallState{
				Backend: "other",
				Rules:   []string{"2222/tcp ALLOW IN Anywhere"},
			},
			port: 22,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleAllowsPort(tt.fw, tt.port)
			if got != tt.want {
				t.Fatalf("ruleAllowsPort(backend=%q, port=%d) = %v, want %v (rules: %v)",
					tt.fw.Backend, tt.port, got, tt.want, tt.fw.Rules)
			}
		})
	}
}
