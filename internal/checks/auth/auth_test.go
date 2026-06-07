package auth

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

// ---- AUTH001 ----

func TestAUTH001_NilStackNotAssessed(t *testing.T) {
	findings := (&auth001{}).Run(&model.ScanContext{Stack: nil})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Errorf("AUTH001: expected NotAssessed for nil stack, got %+v", findings)
	}
}

func TestAUTH001_EmptyServicesNotAssessed(t *testing.T) {
	findings := (&auth001{}).Run(&model.ScanContext{Stack: &model.Stack{}})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Errorf("AUTH001: expected NotAssessed for empty-services stack, got %+v", findings)
	}
}

func TestAUTH002_NilStackNotAssessed(t *testing.T) {
	findings := (&auth002{}).Run(&model.ScanContext{Stack: nil})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Errorf("AUTH002: expected NotAssessed for nil stack, got %+v", findings)
	}
}

func TestAUTH002_EmptyServicesNotAssessed(t *testing.T) {
	findings := (&auth002{}).Run(&model.ScanContext{Stack: &model.Stack{}})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Errorf("AUTH002: expected NotAssessed for empty-services stack, got %+v", findings)
	}
}

func TestAUTH001_ExposedNoAuth(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "grafana",
				Image: "grafana/grafana:latest",
				Ports: []model.PortMapping{
					{HostIP: "", HostPort: 3000, ContainerPort: 3000, Protocol: "tcp"},
				},
			},
		},
	}}
	findings := (&auth001{}).Run(ctx)
	failCount := 0
	for _, f := range findings {
		if !f.Passed {
			failCount++
		}
	}
	if failCount == 0 {
		t.Errorf("expected at least one warning for exposed service with no auth")
	}
}

func TestAUTH001_AutheliaInStack(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "grafana",
				Image: "grafana/grafana:latest",
				Ports: []model.PortMapping{
					{HostIP: "", HostPort: 3000, ContainerPort: 3000, Protocol: "tcp"},
				},
			},
			{
				Name:  "authelia",
				Image: "authelia/authelia:latest",
			},
		},
	}}
	findings := (&auth001{}).Run(ctx)
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected no warnings when authelia is in stack, got %+v", f)
		}
	}
}

func TestAUTH001_ProxyHasAuth(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "app",
				Image: "myapp:latest",
				Ports: []model.PortMapping{
					{HostIP: "", HostPort: 8080, ContainerPort: 8080, Protocol: "tcp"},
				},
			},
		},
		Proxy: &model.ProxyConfig{
			Kind: model.ProxyTraefik,
			Routes: []model.ProxyRoute{
				{Service: "app", HasAuth: true},
			},
		},
	}}
	findings := (&auth001{}).Run(ctx)
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected no warnings when proxy route has auth, got %+v", f)
		}
	}
}

func TestAUTH001_LoopbackNotFlagged(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "app",
				Image: "myapp:latest",
				Ports: []model.PortMapping{
					{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 8080, Protocol: "tcp"},
				},
			},
		},
	}}
	findings := (&auth001{}).Run(ctx)
	for _, f := range findings {
		if !f.Passed && f.Service == "app" {
			t.Errorf("loopback-bound service should not be flagged, got %+v", f)
		}
	}
}

// ---- AUTH002 ----

func TestAUTH002_GrafanaDefaultCritical(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "grafana",
				Image: "grafana/grafana:10.2",
				// No password override in environment.
				Environment: map[string]string{
					"GF_PATHS_DATA": "/var/lib/grafana",
				},
			},
		},
	}}
	findings := (&auth002{}).Run(ctx)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Errorf("expected critical finding for grafana with default creds")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected critical severity, got %v", f.Severity)
	}
}

func TestAUTH002_GrafanaWithStrongOverride(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "grafana",
				Image: "grafana/grafana:10.2",
				Environment: map[string]string{
					"GF_SECURITY_ADMIN_PASSWORD": "SuperStr0ng!Pass#99",
				},
			},
		},
	}}
	findings := (&auth002{}).Run(ctx)
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected pass when strong password is set, got %+v", f)
		}
	}
}

func TestAUTH002_GrafanaWithReferenceOverride(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "grafana",
				Image: "grafana/grafana:10.2",
				Environment: map[string]string{
					"GF_SECURITY_ADMIN_PASSWORD": "${GRAFANA_PASSWORD}",
				},
			},
		},
	}}
	findings := (&auth002{}).Run(ctx)
	for _, f := range findings {
		if !f.Passed {
			t.Errorf("expected pass when password reference is set, got %+v", f)
		}
	}
}

func TestAUTH002_NoKnownImages(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "app",
				Image: "mycompany/myapp:latest",
			},
		},
	}}
	findings := (&auth002{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass for unknown image, got %+v", findings)
	}
}
