package hardening_test

import (
	"testing"

	// Import the hardening package to trigger init() registrations.
	_ "github.com/jakelamon/keelix/internal/checks/hardening"
	"github.com/jakelamon/keelix/internal/model"
)

// hardened returns a fully-hardened service that should pass every check.
func hardened() *model.Service {
	return &model.Service{
		Name:        "db",
		Image:       "postgres:16",
		User:        "1000:1000",
		ReadOnly:    true,
		SecurityOpt: []string{"no-new-privileges:true"},
		Deploy:      &model.DeployConfig{HasLimits: true, MemoryLimit: "512m", CPULimit: "0.5"},
	}
}

// unsafe returns a service with every hardening issue enabled.
func unsafe() *model.Service {
	return &model.Service{
		Name:       "cache",
		Image:      "redis:latest",
		Privileged: true,
		CapAdd:     []string{"SYS_ADMIN", "NET_ADMIN"},
		Volumes: []model.VolumeMount{
			{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"},
		},
		User:     "", // root
		ReadOnly: false,
		// SecurityOpt: nil (missing no-new-privileges)
		// Deploy: nil (no resource limits)
	}
}

func makeCtx(svcs ...*model.Service) *model.ScanContext {
	return &model.ScanContext{
		Stack: &model.Stack{
			Services: svcs,
		},
	}
}

// findCheck returns the registered check with the given ID.
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

// ---- Empty-stack NotAssessed (QF-1) ----

func TestHRDCompose_EmptyStackNotAssessed(t *testing.T) {
	// HRD001-HRD008 are compose-only checks; an empty stack must return NotAssessed,
	// not a vacuous Pass that would inflate the overall grade.
	for _, id := range []string{"HRD001", "HRD002", "HRD003", "HRD004", "HRD005", "HRD006", "HRD007", "HRD008"} {
		c := findCheck(t, id)
		for _, ctx := range []*model.ScanContext{
			{},                      // nil Stack
			{Stack: &model.Stack{}}, // non-nil Stack, zero services
		} {
			fs := c.Run(ctx)
			if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
				t.Errorf("%s: want 1 NotAssessed finding on empty stack, got %+v", id, fs)
			}
		}
	}
}

// ---- HRD001 ----

func TestHRD001_UnsafeService(t *testing.T) {
	c := findCheck(t, "HRD001")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	var criticals []model.Finding
	for _, f := range findings {
		if f.Severity == model.SeverityCritical && !f.Passed {
			criticals = append(criticals, f)
		}
	}
	if len(criticals) != 1 {
		t.Fatalf("HRD001: want 1 critical finding, got %d: %+v", len(criticals), findings)
	}
	if criticals[0].Service != "cache" {
		t.Errorf("HRD001: want service=cache, got %q", criticals[0].Service)
	}
}

func TestHRD001_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD001")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD001: want single pass finding, got %+v", findings)
	}
}

// ---- HRD002 ----

func TestHRD002_SysAdminIsCritical(t *testing.T) {
	c := findCheck(t, "HRD002")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	hasSysAdminCritical := false
	hasNetAdminWarning := false
	for _, f := range findings {
		if f.Passed {
			continue
		}
		switch f.Resource {
		case "capability SYS_ADMIN":
			if f.Severity != model.SeverityCritical {
				t.Errorf("HRD002: SYS_ADMIN should be Critical, got %s", f.Severity)
			}
			hasSysAdminCritical = true
		case "capability NET_ADMIN":
			if f.Severity != model.SeverityWarning {
				t.Errorf("HRD002: NET_ADMIN should be Warning, got %s", f.Severity)
			}
			hasNetAdminWarning = true
		}
	}
	if !hasSysAdminCritical {
		t.Error("HRD002: no Critical finding for SYS_ADMIN")
	}
	if !hasNetAdminWarning {
		t.Error("HRD002: no Warning finding for NET_ADMIN")
	}
}

func TestHRD002_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD002")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD002: want single pass finding for clean stack, got %+v", findings)
	}
}

// ---- HRD003 ----

func TestHRD003_DockerSocket(t *testing.T) {
	c := findCheck(t, "HRD003")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	var crits []model.Finding
	for _, f := range findings {
		if !f.Passed && f.Severity == model.SeverityCritical {
			crits = append(crits, f)
		}
	}
	if len(crits) != 1 {
		t.Fatalf("HRD003: want 1 critical finding, got %d: %+v", len(crits), findings)
	}
	if crits[0].Service != "cache" {
		t.Errorf("HRD003: want service=cache, got %q", crits[0].Service)
	}
}

func TestHRD003_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD003")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD003: want single pass finding, got %+v", findings)
	}
}

// ---- HRD004 ----

func TestHRD004_RootService(t *testing.T) {
	c := findCheck(t, "HRD004")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	var warns []model.Finding
	for _, f := range findings {
		if !f.Passed && f.Severity == model.SeverityWarning {
			warns = append(warns, f)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("HRD004: want 1 warning finding, got %d: %+v", len(warns), findings)
	}
	if warns[0].Service != "cache" {
		t.Errorf("HRD004: want service=cache, got %q", warns[0].Service)
	}
}

func TestHRD004_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD004")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD004: want single pass finding, got %+v", findings)
	}
}

// ---- HRD005 ----

func TestHRD005_MutableFS(t *testing.T) {
	c := findCheck(t, "HRD005")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	var infos []model.Finding
	for _, f := range findings {
		if !f.Passed && f.Severity == model.SeverityInfo {
			infos = append(infos, f)
		}
	}
	if len(infos) != 1 {
		t.Fatalf("HRD005: want 1 info finding, got %d: %+v", len(infos), findings)
	}
	if infos[0].Service != "cache" {
		t.Errorf("HRD005: want service=cache, got %q", infos[0].Service)
	}
}

func TestHRD005_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD005")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD005: want single pass finding, got %+v", findings)
	}
}

// ---- HRD006 ----

func TestHRD006_MissingNoNewPrivileges(t *testing.T) {
	c := findCheck(t, "HRD006")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	var infos []model.Finding
	for _, f := range findings {
		if !f.Passed && f.Severity == model.SeverityInfo {
			infos = append(infos, f)
		}
	}
	if len(infos) != 1 {
		t.Fatalf("HRD006: want 1 info finding, got %d: %+v", len(infos), findings)
	}
	if infos[0].Service != "cache" {
		t.Errorf("HRD006: want service=cache, got %q", infos[0].Service)
	}
}

func TestHRD006_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD006")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD006: want single pass finding, got %+v", findings)
	}
}

// ---- HRD007 ----

func TestHRD007_NoResourceLimits(t *testing.T) {
	c := findCheck(t, "HRD007")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	var infos []model.Finding
	for _, f := range findings {
		if !f.Passed && f.Severity == model.SeverityInfo {
			infos = append(infos, f)
		}
	}
	if len(infos) != 1 {
		t.Fatalf("HRD007: want 1 info finding, got %d: %+v", len(infos), findings)
	}
	if infos[0].Service != "cache" {
		t.Errorf("HRD007: want service=cache, got %q", infos[0].Service)
	}
}

func TestHRD007_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD007")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD007: want single pass finding, got %+v", findings)
	}
}

// ---- HRD008 ----

func TestHRD008_LatestTag(t *testing.T) {
	c := findCheck(t, "HRD008")
	ctx := makeCtx(hardened(), unsafe())
	findings := c.Run(ctx)

	// redis:latest should flag; postgres:16 should NOT.
	var warns []model.Finding
	for _, f := range findings {
		if !f.Passed && f.Severity == model.SeverityWarning {
			warns = append(warns, f)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("HRD008: want 1 warning (redis:latest), got %d: %+v", len(warns), findings)
	}
	if warns[0].Service != "cache" {
		t.Errorf("HRD008: want service=cache (redis:latest), got %q", warns[0].Service)
	}
}

func TestHRD008_PostgresPins(t *testing.T) {
	c := findCheck(t, "HRD008")
	// Only the hardened service (postgres:16) — should pass.
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD008: want pass for postgres:16, got %+v", findings)
	}
}

func TestHRD008_CleanStack(t *testing.T) {
	c := findCheck(t, "HRD008")
	ctx := makeCtx(hardened())
	findings := c.Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Fatalf("HRD008: want single pass finding, got %+v", findings)
	}
}

// ---- HRD009 ----

func TestHRD009_NilCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "HRD009")
	fs := c.Run(&model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("HRD009: want NotAssessed with nil Collector, got %+v", fs)
	}
}

func TestHRD009_Darwin_NotAssessed(t *testing.T) {
	c := findCheck(t, "HRD009")
	ctx := &model.ScanContext{
		Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("HRD009: want NotAssessed on darwin, got %+v", fs)
	}
}

// TestHRD009_WorldWritable_Warning mirrors a FileFact produced by
// internal/collect/files.go for /var/run/docker.sock with mode "0666".
// Mode is an octal string as emitted by the collector (fmt.Sprintf("%04o", stat.Mode()&0o7777)).
func TestHRD009_WorldWritable_Warning(t *testing.T) {
	c := findCheck(t, "HRD009")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/var/run/docker.sock", Exists: true, Mode: "0666"},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("HRD009: want 1 failing finding for mode 0666, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityWarning {
		t.Errorf("HRD009: want Warning, got %s", fs[0].Severity)
	}
	if fs[0].Resource != "/var/run/docker.sock" {
		t.Errorf("HRD009: want Resource=/var/run/docker.sock, got %q", fs[0].Resource)
	}
}

// TestHRD009_WorldReadable_Warning covers mode 0664 (other-read bit set).
func TestHRD009_WorldReadable_Warning(t *testing.T) {
	c := findCheck(t, "HRD009")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/var/run/docker.sock", Exists: true, Mode: "0664"},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("HRD009: want 1 failing finding for mode 0664, got %+v", fs)
	}
}

// TestHRD009_GroupDockerOnly_Passes covers mode 0660 — owner+group only, no world bits.
func TestHRD009_GroupDockerOnly_Passes(t *testing.T) {
	c := findCheck(t, "HRD009")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/var/run/docker.sock", Exists: true, Mode: "0660"},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("HRD009: want pass for mode 0660, got %+v", fs)
	}
}

// TestHRD009_SocketAbsent_NotAssessed verifies NotAssessed when socket is not in Files.
func TestHRD009_SocketAbsent_NotAssessed(t *testing.T) {
	c := findCheck(t, "HRD009")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files:    []model.FileFact{}, // no docker.sock entry
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("HRD009: want NotAssessed when socket absent from Files, got %+v", fs)
	}
}

// TestHRD009_ExistsFalse_NotAssessed covers Exists=false (socket not found by collector).
func TestHRD009_ExistsFalse_NotAssessed(t *testing.T) {
	c := findCheck(t, "HRD009")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/var/run/docker.sock", Exists: false},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("HRD009: want NotAssessed when Exists=false, got %+v", fs)
	}
}

// ---- HRD010 ----

func TestHRD010_NilCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "HRD010")
	fs := c.Run(&model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("HRD010: want NotAssessed with nil Collector, got %+v", fs)
	}
}

func TestHRD010_Darwin_NotAssessed(t *testing.T) {
	c := findCheck(t, "HRD010")
	ctx := &model.ScanContext{
		Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("HRD010: want NotAssessed on darwin, got %+v", fs)
	}
}

// TestHRD010_NonRootDockerGroup_Warning mirrors a ProcessFact produced by
// internal/collect/processes.go for a non-root user whose process is in the
// docker group. The collector populates Groups via `id -Gn <uid>` or /etc/group
// (implementation-dependent; the fact shape is the same either way).
func TestHRD010_NonRootDockerGroup_Warning(t *testing.T) {
	c := findCheck(t, "HRD010")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				{Comm: "bash", PID: 2000, UID: 1000, Groups: []string{"users", "docker", "plugdev"}},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("HRD010: want 1 failing finding for non-root docker group, got %+v", fs)
	}
	if fs[0].Severity != model.SeverityWarning {
		t.Errorf("HRD010: want Warning, got %s", fs[0].Severity)
	}
}

// TestHRD010_RootInDockerGroup_Passes verifies UID 0 is not flagged (root is
// already privileged; the concern is non-root escalation).
func TestHRD010_RootInDockerGroup_Passes(t *testing.T) {
	c := findCheck(t, "HRD010")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				{Comm: "dockerd", PID: 1, UID: 0, Groups: []string{"root", "docker"}},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("HRD010: want pass when only root is in docker group, got %+v", fs)
	}
}

// TestHRD010_AgentProcessSkipped_Passes verifies that an agent process (e.g.
// "openclaw") in the docker group is NOT flagged by HRD010 — AGT003 covers it.
func TestHRD010_AgentProcessSkipped_Passes(t *testing.T) {
	c := findCheck(t, "HRD010")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				// Only an agent process in docker group — must not double-fire.
				{Comm: "openclaw", PID: 3000, UID: 1000, Groups: []string{"docker"}},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("HRD010: want pass when only agent process in docker group (covered by AGT003), got %+v", fs)
	}
}

// TestHRD010_DeduplicatesByUID verifies one finding per UID even with multiple processes.
func TestHRD010_DeduplicatesByUID(t *testing.T) {
	c := findCheck(t, "HRD010")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				{Comm: "bash", PID: 2000, UID: 1000, Groups: []string{"docker"}},
				{Comm: "python3", PID: 2001, UID: 1000, Groups: []string{"docker"}},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("HRD010: want 1 deduplicated finding for two processes with same UID, got %d: %+v", len(fs), fs)
	}
	if fs[0].Passed {
		t.Error("HRD010: single finding must be failing")
	}
}

// TestHRD010_NonDockerGroup_Passes verifies a non-root user without docker group passes.
func TestHRD010_NonDockerGroup_Passes(t *testing.T) {
	c := findCheck(t, "HRD010")
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Processes: []model.ProcessFact{
				{Comm: "bash", PID: 2000, UID: 1000, Groups: []string{"users", "audio"}},
			},
		},
	}
	fs := c.Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("HRD010: want pass for non-docker group, got %+v", fs)
	}
}
