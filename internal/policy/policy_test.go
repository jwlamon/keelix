package policy

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func stackWith(svc model.Service) *model.Stack {
	return &model.Stack{Services: []*model.Service{&svc}}
}

func TestDenyImageGlob(t *testing.T) {
	p := Policy{DenyImages: []string{"*:latest"}}
	f := p.Evaluate(stackWith(model.Service{Name: "web", Image: "nginx:latest"}))
	if len(f) != 1 || f[0].Severity != model.SeverityWarning {
		t.Fatalf("expected 1 warning for :latest, got %+v", f)
	}
}

func TestDenyHostPort(t *testing.T) {
	p := Policy{DenyHostPorts: []int{2375}}
	svc := model.Service{Name: "docker", Ports: []model.PortMapping{{HostPort: 2375}}}
	f := p.Evaluate(stackWith(svc))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for denied port, got %d", len(f))
	}
}

func TestCleanStackNoFindings(t *testing.T) {
	p := Policy{DenyImages: []string{"*:latest"}, DenyHostPorts: []int{2375}}
	f := p.Evaluate(stackWith(model.Service{Name: "web", Image: "nginx:1.27", Ports: []model.PortMapping{{HostPort: 8080}}}))
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}

func TestDenyPrivileged(t *testing.T) {
	p := Policy{DenyPrivileged: true}
	f := p.Evaluate(stackWith(model.Service{Name: "app", Privileged: true}))
	if len(f) != 1 || f[0].Severity != model.SeverityCritical {
		t.Fatalf("expected 1 critical for privileged container, got %+v", f)
	}
}

func TestRequireLabel(t *testing.T) {
	p := Policy{RequireLabel: "org.example.team"}
	// service without the required label
	f := p.Evaluate(stackWith(model.Service{Name: "app"}))
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for missing label, got %d", len(f))
	}
	// service with the required label — no findings
	f2 := p.Evaluate(stackWith(model.Service{Name: "app", Labels: map[string]string{"org.example.team": "platform"}}))
	if len(f2) != 0 {
		t.Fatalf("expected no findings when label present, got %+v", f2)
	}
}
