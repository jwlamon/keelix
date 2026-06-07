package firewall_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/firewall"
	"github.com/jwlamon/keelix/internal/model"
)

// makeStack builds a stack with service "db" publishing 5432 to all interfaces.
func makeStack(firewall *model.FirewallConfig, extraSvcs ...*model.Service) *model.Stack {
	svcs := []*model.Service{
		{
			Name:  "db",
			Image: "postgres:16",
			Ports: []model.PortMapping{
				{HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
			},
		},
	}
	svcs = append(svcs, extraSvcs...)
	return &model.Stack{
		Services: svcs,
		Firewall: firewall,
	}
}

func makeFirewall(denies []int, hasDockerUser bool) *model.FirewallConfig {
	rules := make([]model.FirewallRule, 0, len(denies))
	for _, p := range denies {
		rules = append(rules, model.FirewallRule{Action: "deny", Port: p, Protocol: "tcp"})
	}
	return &model.FirewallConfig{
		Engine:             model.FirewallUFW,
		DefaultIncoming:    "deny",
		Rules:              rules,
		HasDockerUserChain: hasDockerUser,
	}
}

func runCheck(id string, ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c.Run(ctx)
		}
	}
	panic(id + " not registered")
}

// ---- FW001 ----

func TestFW001_Critical_FirewallDeniesPublishedPort(t *testing.T) {
	fw := makeFirewall([]int{5432}, false)
	ctx := &model.ScanContext{
		Stack:    makeStack(fw),
		Intended: map[int]bool{},
	}
	findings := runCheck("FW001", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected Critical, got %v", f.Severity)
	}
	if f.Service != "db" {
		t.Errorf("expected service 'db', got %q", f.Service)
	}
}

func TestFW001_Pass_NoConflict(t *testing.T) {
	// Firewall denies 9999 (not a published port) — no conflict.
	fw := makeFirewall([]int{9999}, false)
	ctx := &model.ScanContext{
		Stack:    makeStack(fw),
		Intended: map[int]bool{},
	}
	findings := runCheck("FW001", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestFW001_NilFirewall_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeStack(nil)}
	if runCheck("FW001", ctx) != nil {
		t.Error("expected nil when firewall is nil")
	}
}

func TestFW001_ProbeConfirmsReachable_AppendedToEvidence(t *testing.T) {
	fw := makeFirewall([]int{5432}, false)
	probe := &model.ProbeResult{
		Reachable: map[int]model.PortProbe{
			5432: {Port: 5432, Open: true},
		},
	}
	ctx := &model.ScanContext{
		Stack:    makeStack(fw),
		Probe:    probe,
		Intended: map[int]bool{},
	}
	findings := runCheck("FW001", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Passed {
		t.Error("finding should not be passed")
	}
	// Evidence should mention confirmed reachable.
	if findings[0].Evidence == "" {
		t.Error("evidence should not be empty")
	}
}

// ---- FW002 ----

func TestFW002_Warning_SensitivePortOnAllInterfaces(t *testing.T) {
	// 5432 is sensitive and published to 0.0.0.0 (default — no HostIP set).
	ctx := &model.ScanContext{
		Stack:    makeStack(nil),
		Intended: map[int]bool{},
	}
	findings := runCheck("FW002", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityWarning {
		t.Errorf("expected Warning, got %v", findings[0].Severity)
	}
	if findings[0].Service != "db" {
		t.Errorf("expected service 'db', got %q", findings[0].Service)
	}
}

func TestFW002_Pass_Loopback(t *testing.T) {
	stack := &model.Stack{
		Services: []*model.Service{
			{
				Name:  "db",
				Image: "postgres:16",
				Ports: []model.PortMapping{
					{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432, Protocol: "tcp"},
				},
			},
		},
	}
	ctx := &model.ScanContext{Stack: stack, Intended: map[int]bool{}}
	findings := runCheck("FW002", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding for loopback-bound port, got %v", findings)
	}
}

func TestFW002_Pass_Intended(t *testing.T) {
	ctx := &model.ScanContext{
		Stack:    makeStack(nil),
		Intended: map[int]bool{5432: true},
	}
	findings := runCheck("FW002", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding when intended, got %v", findings)
	}
}

// TestFW002_EmptyStack_NotAssessed verifies QF-1: a compose-only check must
// return NotAssessed (not a vacuous Pass) when the stack has no services.
func TestFW002_EmptyStack_NotAssessed(t *testing.T) {
	for _, ctx := range []*model.ScanContext{
		{},                      // nil Stack
		{Stack: &model.Stack{}}, // non-nil Stack, zero services
	} {
		fs := runCheck("FW002", ctx)
		if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
			t.Errorf("FW002: want 1 NotAssessed finding on empty stack, got %+v", fs)
		}
	}
}

// ---- FW003 ----

func TestFW003_Warning_HostNetworkMode(t *testing.T) {
	svc := &model.Service{Name: "sidecar", NetworkMode: "host"}
	ctx := &model.ScanContext{Stack: makeStack(nil, svc)}
	findings := runCheck("FW003", ctx)
	// We should get at least 1 finding for "sidecar"
	found := false
	for _, f := range findings {
		if f.Service == "sidecar" && f.Severity == model.SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Warning finding for service 'sidecar', got %v", findings)
	}
}

func TestFW003_Pass_NormalNetworkMode(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeStack(nil)}
	findings := runCheck("FW003", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

// TestFW003_EmptyStack_NotAssessed verifies QF-1: a compose-only check must
// return NotAssessed (not a vacuous Pass) when the stack has no services.
func TestFW003_EmptyStack_NotAssessed(t *testing.T) {
	for _, ctx := range []*model.ScanContext{
		{},                      // nil Stack
		{Stack: &model.Stack{}}, // non-nil Stack, zero services
	} {
		fs := runCheck("FW003", ctx)
		if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
			t.Errorf("FW003: want 1 NotAssessed finding on empty stack, got %+v", fs)
		}
	}
}

// ---- FW004 ----

func TestFW004_Info_NoDockerUserChain(t *testing.T) {
	fw := makeFirewall(nil, false) // no DOCKER-USER chain
	ctx := &model.ScanContext{Stack: makeStack(fw)}
	findings := runCheck("FW004", ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != model.SeverityInfo {
		t.Errorf("expected Info, got %v", findings[0].Severity)
	}
	if findings[0].Passed {
		t.Error("finding should not be passed")
	}
}

func TestFW004_Pass_HasDockerUserChain(t *testing.T) {
	fw := makeFirewall(nil, true) // DOCKER-USER present
	ctx := &model.ScanContext{Stack: makeStack(fw)}
	findings := runCheck("FW004", ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected single pass finding, got %v", findings)
	}
}

func TestFW004_NilFirewall_NotApplicable(t *testing.T) {
	ctx := &model.ScanContext{Stack: makeStack(nil)}
	if runCheck("FW004", ctx) != nil {
		t.Error("expected nil when firewall is nil")
	}
}

func TestFW004_NoPublicPorts_NotApplicable(t *testing.T) {
	// Stack with firewall but all ports are loopback-bound.
	fw := makeFirewall(nil, false)
	stack := &model.Stack{
		Firewall: fw,
		Services: []*model.Service{
			{
				Name: "db",
				Ports: []model.PortMapping{
					{HostIP: "127.0.0.1", HostPort: 5432, ContainerPort: 5432},
				},
			},
		},
	}
	ctx := &model.ScanContext{Stack: stack}
	if runCheck("FW004", ctx) != nil {
		t.Error("expected nil when no services publish to all interfaces")
	}
}

// ---- FW005 ----

func TestFW005_NilCollector_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: nil}
	findings := runCheck("FW005", ctx)
	if len(findings) == 0 {
		t.Fatal("FW005: expected at least one finding, got none")
	}
	if findings[0].Status != model.StatusNotAssessed {
		t.Errorf("FW005: want StatusNotAssessed for nil collector, got %v", findings[0].Status)
	}
}

func TestFW005_Darwin_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "darwin"},
		},
	}
	findings := runCheck("FW005", ctx)
	if len(findings) == 0 {
		t.Fatal("FW005: expected at least one finding, got none")
	}
	if findings[0].Status != model.StatusNotAssessed {
		t.Errorf("FW005: want StatusNotAssessed on darwin, got %v", findings[0].Status)
	}
}

func TestFW005_TCPNonLoopback_Critical_ViaConfig(t *testing.T) {
	// Supply a docker-daemon ConfigFact with tcp://0.0.0.0:2375.
	fact := model.ConfigFact{
		SchemaID:    "docker-daemon",
		SchemaKnown: true,
		Source:      "/etc/docker/daemon.json",
		Values:      map[string]string{"hosts": "tcp://0.0.0.0:2375,unix:///var/run/docker.sock"},
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := runCheck("FW005", ctx)
	if len(findings) == 0 {
		t.Fatal("FW005: expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Fatalf("FW005: expected failing finding for tcp://0.0.0.0:2375, got pass")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("FW005: want Critical severity, got %v", f.Severity)
	}
}

func TestFW005_TCPLoopback_Pass_ViaConfig(t *testing.T) {
	// tcp://127.0.0.1 is loopback — should not fire.
	fact := model.ConfigFact{
		SchemaID:    "docker-daemon",
		SchemaKnown: true,
		Source:      "/etc/docker/daemon.json",
		Values:      map[string]string{"hosts": "tcp://127.0.0.1:2375,unix:///var/run/docker.sock"},
	}
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{fact},
		},
	}
	findings := runCheck("FW005", ctx)
	if len(findings) == 0 {
		t.Fatal("FW005: expected at least one finding")
	}
	if !findings[0].Passed {
		t.Fatalf("FW005: expected pass for loopback-only TCP bind, got fail: %+v", findings[0])
	}
}

func TestFW005_TCPNonLoopback_Critical_ViaProcess(t *testing.T) {
	// Simulate dockerd process arg -H tcp://0.0.0.0:2376.
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				{
					Comm: "dockerd",
					Args: []string{"dockerd", "-H", "tcp://0.0.0.0:2376"},
				},
			},
		},
	}
	findings := runCheck("FW005", ctx)
	if len(findings) == 0 {
		t.Fatal("FW005: expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Fatalf("FW005: expected fail for dockerd -H tcp://0.0.0.0:2376, got pass")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("FW005: want Critical severity, got %v", f.Severity)
	}
}

func TestFW005_NoTCP_Pass(t *testing.T) {
	// Linux, collector present, no TCP host — should pass.
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
		},
	}
	findings := runCheck("FW005", ctx)
	if len(findings) == 0 {
		t.Fatal("FW005: expected at least one finding")
	}
	if !findings[0].Passed {
		t.Fatalf("FW005: expected pass when no TCP host configured, got fail: %+v", findings[0])
	}
}

// TestFW005_ProcessArg_AllInterfaces_Critical exercises the dockerd process-arg
// path: a ProcessFact with Comm="dockerd" and Args=[..., "-H", "tcp://0.0.0.0:2375"]
// mirrors what internal/collect/processes.go produces from `ps -eo pid,uid,comm,args`.
func TestFW005_ProcessArg_AllInterfaces_Critical(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{
					"/usr/bin/dockerd",
					"-H", "unix:///var/run/docker.sock",
					"-H", "tcp://0.0.0.0:2375",
					"--containerd=/run/containerd/containerd.sock",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 {
		t.Fatalf("FW005: want 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("FW005: want Critical, got %s", f.Severity)
	}
	if f.Passed {
		t.Error("FW005: finding must not be passed")
	}
	if !f.Fatal {
		t.Error("FW005: finding must be Fatal")
	}
	if f.Metadata["port"] != "2375" {
		t.Errorf("FW005: want Metadata[port]=2375, got %q", f.Metadata["port"])
	}
}

// TestFW005_ProcessArg_RoutableIP_Critical covers -H tcp://<LAN IP>:2376.
func TestFW005_ProcessArg_RoutableIP_Critical(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "tcp://192.168.1.10:2376"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW005: want 1 failing finding for routable IP, got %+v", fs)
	}
	if fs[0].Metadata["port"] != "2376" {
		t.Errorf("FW005: want port 2376, got %q", fs[0].Metadata["port"])
	}
}

// TestFW005_ProcessArg_Loopback_Passes verifies loopback-only does not fire.
func TestFW005_ProcessArg_Loopback_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "tcp://127.0.0.1:2375"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW005: want pass for loopback TCP, got %+v", fs)
	}
}

// TestFW005_UnixOnly_Passes verifies Unix-socket-only dockerd passes.
func TestFW005_UnixOnly_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "unix:///var/run/docker.sock"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW005: want pass for Unix socket only, got %+v", fs)
	}
}

// TestFW005_DaemonJSON_ConfigFact_Critical exercises the ConfigFact path that
// mirrors what the SLICE-D docker-daemon parser (collectConfig → parseDaemonJSON)
// produces: SchemaID="docker-daemon", Values["hosts"]="unix:///var/run/docker.sock,tcp://0.0.0.0:2375".
func TestFW005_DaemonJSON_ConfigFact_Critical(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				Source:      "/etc/docker/daemon.json",
				SchemaID:    "docker-daemon",
				SchemaKnown: true,
				Values: map[string]string{
					"hosts": "unix:///var/run/docker.sock,tcp://0.0.0.0:2375",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW005: want 1 failing finding from ConfigFact, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Errorf("FW005: want Critical from ConfigFact path, got %s", fs[0].Severity)
	}
	if fs[0].Metadata["port"] != "2375" {
		t.Errorf("FW005: want Metadata[port]=2375 from ConfigFact path, got %q", fs[0].Metadata["port"])
	}
}

// TestFW005_DaemonJSON_UnixOnly_Passes covers daemon.json with only a Unix host.
func TestFW005_DaemonJSON_UnixOnly_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				Source:      "/etc/docker/daemon.json",
				SchemaID:    "docker-daemon",
				SchemaKnown: true,
				Values: map[string]string{
					"hosts": "unix:///var/run/docker.sock",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW005: want pass for daemon.json Unix-only hosts, got %+v", fs)
	}
}

// TestFW005_NoDockerd_Passes verifies no dockerd process + no daemon config passes.
func TestFW005_NoDockerd_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{{Comm: "nginx", PID: 100, UID: 0}},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW005: want pass when no dockerd, got %+v", fs)
	}
}

// ---- FW006 ----

func TestFW006_NilCollector_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("FW006: want NotAssessed with nil Collector, got %+v", fs)
	}
}

func TestFW006_Darwin_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
	}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("FW006: want NotAssessed on darwin, got %+v", fs)
	}
}

// TestFW006_AnonAuthTrue_Webhook_Passes mirrors a ProcessFact for a k3s-server
// with --anonymous-auth=true but --authorization-mode=Webhook. Per R3-1 correct
// semantics, Webhook rejects anonymous requests at authz — this is PASS.
// (The old test name "_Critical" encoded pre-R3-1 semantics and has been updated.)
func TestFW006_AnonAuthTrue_Webhook_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "k3s-server",
				PID:  555,
				UID:  0,
				Args: []string{
					"/usr/local/bin/k3s",
					"server",
					"--anonymous-auth=true",
					"--authorization-mode=Webhook",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006: want PASS for --anonymous-auth=true + Webhook (R3-1 case 5), got %+v", fs)
	}
}

// TestFW006_AnonFalse_AbsentMode_Passes is the R3-1 matrix case 1:
// --anonymous-auth=false with no --authorization-mode → PASS.
// Anon is rejected at authN so the authz mode is irrelevant.
// This replaces the old TestFW006_MissingAuthMode_Critical which encoded
// the wrong (pre-R3-1) semantics.
func TestFW006_AnonFalse_AbsentMode_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "kubelet",
				PID:  666,
				UID:  0,
				Args: []string{
					"/usr/bin/kubelet",
					"--anonymous-auth=false",
					// --authorization-mode is intentionally absent
					"--config=/etc/kubernetes/kubelet.conf",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 1: want PASS for --anonymous-auth=false + absent mode, got %+v", fs)
	}
}

// TestFW006_HardenedKubelet_Passes covers --anonymous-auth=false + --authorization-mode=Webhook.
func TestFW006_HardenedKubelet_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "kubelet",
				PID:  777,
				UID:  0,
				Args: []string{
					"/usr/bin/kubelet",
					"--anonymous-auth=false",
					"--authorization-mode=Webhook",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006: want pass for hardened kubelet, got %+v", fs)
	}
}

// TestFW006_NoKubelet_Passes verifies no k3s/kubelet process gives a pass.
func TestFW006_NoKubelet_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{{Comm: "dockerd", PID: 100, UID: 0}},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006: want pass when no k3s/kubelet, got %+v", fs)
	}
}

// ---- FIX-5 TDD tests ----

// ---- R3-1 exhaustive kubeletAnonAuth matrix ----

// makeKubeletCtx builds a ScanContext with a kubelet process using the given args.
func makeKubeletCtx(comm string, args []string) *model.ScanContext {
	return &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				{Comm: comm, PID: 100, UID: 0, Args: args},
			},
		},
	}
}

// R3-1 case 2: space-form --anonymous-auth false + --authorization-mode Webhook → PASS.
// Both flags use the "key space value" form — a standard systemd kubelet invocation.
func TestFW006_R3_1_SpaceAnonFalse_SpaceWebhook_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth", "false",
		"--authorization-mode", "Webhook",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 2: want PASS for space-form anon=false + Webhook, got %+v", fs)
	}
}

// R3-1 case 3: --authorization-mode=Webhook only (no --anonymous-auth) → PASS.
// Webhook authorizer rejects unauthenticated requests.
func TestFW006_R3_1_WebhookOnly_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--authorization-mode=Webhook",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 3: want PASS for --authorization-mode=Webhook only, got %+v", fs)
	}
}

// R3-1 case 4: --anonymous-auth=true + --authorization-mode=AlwaysAllow → FAIL.
func TestFW006_R3_1_AnonTrue_AlwaysAllow_Fails(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth=true",
		"--authorization-mode=AlwaysAllow",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 4: want FAIL for anon=true + AlwaysAllow, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Errorf("FW006 R3-1 case 4: want Critical, got %s", fs[0].Severity)
	}
}

// R3-1 case 5: --anonymous-auth true (space form) + --authorization-mode=Webhook → PASS.
// Space-form anon=true but Webhook authorizer → anonymous requests are rejected by authz.
func TestFW006_R3_1_SpaceAnonTrue_Webhook_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth", "true",
		"--authorization-mode=Webhook",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 5: want PASS for space-form anon=true + Webhook, got %+v", fs)
	}
}

// R3-1 case 6: --authorization-mode=AlwaysAllow (no --anonymous-auth explicit) → FAIL.
// Default anon (not false) + AlwaysAllow means every unauthenticated request is authorized.
func TestFW006_R3_1_AlwaysAllowOnly_Fails(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--authorization-mode=AlwaysAllow",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 6: want FAIL for --authorization-mode=AlwaysAllow alone, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Errorf("FW006 R3-1 case 6: want Critical, got %s", fs[0].Severity)
	}
}

// R3-1 case 7: --authorization-mode AlwaysAllow (space form) → FAIL.
// Must detect the space form of the authorization-mode flag.
func TestFW006_R3_1_SpaceAlwaysAllow_Fails(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--authorization-mode", "AlwaysAllow",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 7: want FAIL for space-form --authorization-mode AlwaysAllow, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Errorf("FW006 R3-1 case 7: want Critical, got %s", fs[0].Severity)
	}
}

// R3-1 case 8: --authorization-mode=AlwaysAllow,RBAC (comma list includes AlwaysAllow) → FAIL.
// A comma-delimited list containing AlwaysAllow means any request passes authz.
func TestFW006_R3_1_AlwaysAllowRBAC_Fails(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--authorization-mode=AlwaysAllow,RBAC",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 8: want FAIL for --authorization-mode=AlwaysAllow,RBAC, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Errorf("FW006 R3-1 case 8: want Critical, got %s", fs[0].Severity)
	}
}

// R3-1 case 9: bare kubelet (no flags) → PASS (not a false RED).
// When neither --anonymous-auth nor --authorization-mode is specified, no
// confirmed-open signal exists — do not fire on absence alone.
func TestFW006_R3_1_BareKubelet_NoFlags_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{"/usr/bin/kubelet"})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R3-1 case 9: want PASS for bare kubelet with no flags, got %+v", fs)
	}
}

// R3-1 bonus: Node,RBAC authorizer chain (no AlwaysAllow) → PASS.
func TestFW006_R3_1_NodeRBAC_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--authorization-mode=Node,RBAC",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R3-1 bonus: want PASS for --authorization-mode=Node,RBAC, got %+v", fs)
	}
}

// ---- FIX-5 TDD tests ----

// TestFW005_TailnetBind_Overlay_NotInternet verifies that a dockerd listening on
// a CGNAT/tailnet address (100.64.x.x) produces ExposureOverlay, not the
// previously hardcoded ExposureInternet. This was the "false RED" defect.
func TestFW005_TailnetBind_Overlay_NotInternet(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "tcp://100.64.1.5:2375"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 {
		t.Fatalf("FW005: want 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	// Must still fire (tailnet exposure is a finding) but NOT be classified Internet.
	if f.Passed {
		t.Fatal("FW005: tailnet dockerd must produce a failing finding")
	}
	if f.ExposureClass == model.ExposureInternet {
		t.Errorf("FW005: tailnet bind 100.64.x.x must NOT produce ExposureInternet (false RED); got %v", f.ExposureClass)
	}
	if f.ExposureClass != model.ExposureOverlay {
		t.Errorf("FW005: tailnet bind 100.64.x.x must produce ExposureOverlay; got %v", f.ExposureClass)
	}
}

// TestFW005_WildcardBind_ExposureInternet is a regression guard: 0.0.0.0 dockerd
// must still produce ExposureInternet after the BindClass refactor.
func TestFW005_WildcardBind_ExposureInternet(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "tcp://0.0.0.0:2375"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW005: want 1 failing finding for 0.0.0.0, got %+v", fs)
	}
	if fs[0].ExposureClass != model.ExposureInternet {
		t.Errorf("FW005: 0.0.0.0 dockerd must produce ExposureInternet; got %v", fs[0].ExposureClass)
	}
}

// TestFW005_LANBind_ExposureLAN verifies RFC1918 dockerd binds produce ExposureLAN.
func TestFW005_LANBind_ExposureLAN(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "tcp://192.168.1.10:2376"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW005: want 1 failing finding for LAN IP, got %+v", fs)
	}
	if fs[0].ExposureClass != model.ExposureLAN {
		t.Errorf("FW005: RFC1918 dockerd bind must produce ExposureLAN; got %v", fs[0].ExposureClass)
	}
}

// TestFW006_WildcardBind_Internet verifies that a kubelet bound to 0.0.0.0
// (the default) produces ExposureInternet, not the previously hardcoded
// ExposureLAN. This was the scoring defect: 0.0.0.0 should score 1.0x not 0.35x.
func TestFW006_WildcardBind_Internet(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "kubelet",
				PID:  666,
				UID:  0,
				// No --address / --bind-address flag => defaults to 0.0.0.0.
				Args: []string{"/usr/bin/kubelet", "--anonymous-auth=true"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006: want 1 failing finding, got %+v", fs)
	}
	if fs[0].ExposureClass != model.ExposureInternet {
		t.Errorf("FW006: default-bind (0.0.0.0) kubelet must produce ExposureInternet; got %v", fs[0].ExposureClass)
	}
}

// TestFW006_LANBind_LAN verifies a kubelet bound to an RFC1918 address produces
// ExposureLAN (correct per the address) rather than ExposureInternet or ExposureLAN
// as a hardcode.
func TestFW006_LANBind_LAN(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "kubelet",
				PID:  777,
				UID:  0,
				Args: []string{"/usr/bin/kubelet", "--anonymous-auth=true", "--address=192.168.1.50"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006: want 1 failing finding for LAN bind, got %+v", fs)
	}
	if fs[0].ExposureClass != model.ExposureLAN {
		t.Errorf("FW006: RFC1918 kubelet bind must produce ExposureLAN; got %v", fs[0].ExposureClass)
	}
}

// TestFW006_AnonFalse_AlwaysAllow_Passes covers R3-1 semantics: when
// --anonymous-auth=false the kubelet rejects anonymous requests at authN,
// so even --authorization-mode=AlwaysAllow cannot be reached by an anonymous
// caller. R3-1 rule: PASS when --anonymous-auth=false regardless of authz mode.
// (The old R2-1 test encoded the opposite expectation; R3-1 supersedes it.)
func TestFW006_AnonFalse_AlwaysAllow_Passes(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "kubelet",
				PID:  999,
				UID:  0,
				Args: []string{
					"/usr/bin/kubelet",
					"--anonymous-auth=false",
					"--authorization-mode=AlwaysAllow",
				},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006: want PASS for --anonymous-auth=false + AlwaysAllow (R3-1), got %+v", fs)
	}
}

// TestFW005_EmptyHostWildcard_ExposureInternet is the R2-5 TDD test:
// tcp://:PORT (Docker's documented wildcard form with empty host) must map
// bindHostOf to "0.0.0.0", which BindClass classifies as ExposureInternet.
// Before the fix, bindHostOf returns "" → BindClass returns ExposureUnknown.
func TestFW005_EmptyHostWildcard_ExposureInternet(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "dockerd",
				PID:  1234,
				UID:  0,
				Args: []string{"/usr/bin/dockerd", "-H", "tcp://:2375"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW005", ctx)
	if len(fs) != 1 {
		t.Fatalf("FW005: want 1 finding for tcp://:2375, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Passed {
		t.Fatal("FW005: tcp://:2375 (wildcard) must produce a failing finding")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("FW005: want Critical severity for tcp://:2375, got %v", f.Severity)
	}
	if f.ExposureClass != model.ExposureInternet {
		t.Errorf("FW005: tcp://:2375 must produce ExposureInternet; got %v (R2-5 bug: empty host → Unknown)", f.ExposureClass)
	}
}

// ---- R4-2: k3s --kubelet-arg unwrap, case-insensitive value, last-wins ----

// TestFW006_R4_2_KubeletArgWrapped_AlwaysAllow_Fails verifies that
// --kubelet-arg=anonymous-auth=true + --kubelet-arg=authorization-mode=AlwaysAllow
// (k3s wrapping form) correctly fires FW006.
func TestFW006_R4_2_KubeletArgWrapped_AlwaysAllow_Fails(t *testing.T) {
	ctx := makeKubeletCtx("k3s-server", []string{
		"/usr/local/bin/k3s",
		"server",
		"--kubelet-arg=anonymous-auth=true",
		"--kubelet-arg=authorization-mode=AlwaysAllow",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R4-2 (k3s wrap AlwaysAllow): want FAIL, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityCritical {
		t.Errorf("FW006 R4-2: want Critical, got %s", fs[0].Severity)
	}
}

// TestFW006_R4_2_KubeletArgWrapped_AnonTrue_Fails verifies that
// --kubelet-arg=anonymous-auth=true (k3s, no mode override) fires FW006 — the
// anon-true-no-mode path.
func TestFW006_R4_2_KubeletArgWrapped_AnonTrue_NoMode_Fails(t *testing.T) {
	ctx := makeKubeletCtx("k3s-server", []string{
		"/usr/local/bin/k3s",
		"server",
		"--kubelet-arg=anonymous-auth=true",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R4-2 (k3s wrap anon-true only): want FAIL, got %+v", fs)
	}
}

// TestFW006_R4_2_KubeletArgWrapped_AnonFalse_Passes verifies that
// --kubelet-arg=anonymous-auth=false (k3s hardened) does NOT fire FW006.
func TestFW006_R4_2_KubeletArgWrapped_AnonFalse_Passes(t *testing.T) {
	ctx := makeKubeletCtx("k3s-server", []string{
		"/usr/local/bin/k3s",
		"server",
		"--kubelet-arg=anonymous-auth=false",
		"--kubelet-arg=authorization-mode=Webhook",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R4-2 (k3s wrap hardened): want PASS, got %+v", fs)
	}
}

// TestFW006_R4_2_CaseInsensitiveFalse_Passes verifies that --anonymous-auth=False
// (capital F, as produced by some pflag implementations) is treated as false → PASS.
func TestFW006_R4_2_CaseInsensitiveFalse_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth=False",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R4-2 (--anonymous-auth=False): want PASS, got %+v", fs)
	}
}

// TestFW006_R4_2_CaseInsensitiveTrue_Fires verifies that --anonymous-auth=TRUE
// is treated as true.
func TestFW006_R4_2_CaseInsensitiveTrue_Fires(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth=TRUE",
		"--authorization-mode=AlwaysAllow",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R4-2 (--anonymous-auth=TRUE): want FAIL, got %+v", fs)
	}
}

// TestFW006_R4_2_LastWins_TrueOverriddenByFalse_Passes verifies that when
// --anonymous-auth appears twice the last value wins: true then false → PASS.
func TestFW006_R4_2_LastWins_TrueOverriddenByFalse_Passes(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth=true",
		"--anonymous-auth=false",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("FW006 R4-2 (last-wins false): want PASS, got %+v", fs)
	}
}

// TestFW006_R4_2_LastWins_FalseOverriddenByTrue_Fires verifies last-wins when
// false appears first: --anonymous-auth=false --anonymous-auth=true → FAIL.
func TestFW006_R4_2_LastWins_FalseOverriddenByTrue_Fires(t *testing.T) {
	ctx := makeKubeletCtx("kubelet", []string{
		"/usr/bin/kubelet",
		"--anonymous-auth=false",
		"--anonymous-auth=true",
		"--authorization-mode=AlwaysAllow",
	})
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006 R4-2 (last-wins true): want FAIL, got %+v", fs)
	}
}

// TestFW005_TailnetBind_Overlay verifies a kubelet bound to a CGNAT/tailnet
// address produces ExposureOverlay.
func TestFW006_TailnetBind_Overlay(t *testing.T) {
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{
			{
				Comm: "k3s-server",
				PID:  888,
				UID:  0,
				Args: []string{"/usr/local/bin/k3s", "server", "--anonymous-auth=true", "--bind-address=100.64.2.3"},
			},
		},
	}
	ctx := &model.ScanContext{Collector: sigs}
	fs := runCheck("FW006", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("FW006: want 1 failing finding for tailnet bind, got %+v", fs)
	}
	if fs[0].ExposureClass != model.ExposureOverlay {
		t.Errorf("FW006: tailnet kubelet bind must produce ExposureOverlay; got %v", fs[0].ExposureClass)
	}
}
