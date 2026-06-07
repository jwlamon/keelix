package aiagent_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func agentProcess(comm string, groups []string) model.ProcessFact {
	return model.ProcessFact{Comm: comm, PID: 100, UID: 1000, Groups: groups}
}

func TestAGT003_DockerGroup_Linux_Critical(t *testing.T) {
	c := findCheck(t, "AGT003")
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{agentProcess("openclaw", []string{"docker", "users"})},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT003" && f.IsFail() {
			found = true
			if f.Severity != model.SeverityCritical {
				t.Errorf("AGT003 linux docker: want Critical, got %s", f.Severity)
			}
			if f.BaseImpact != 9.0 {
				t.Errorf("AGT003 linux docker: want BaseImpact 9.0, got %f", f.BaseImpact)
			}
		}
	}
	if !found {
		t.Fatal("AGT003: linux docker group must fire Critical")
	}
}

func TestAGT003_DockerGroup_Darwin_Warning(t *testing.T) {
	c := findCheck(t, "AGT003")
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "darwin"},
		Processes: []model.ProcessFact{agentProcess("openclaw", []string{"docker", "users"})},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT003" && f.IsFail() {
			found = true
			if f.Severity != model.SeverityWarning {
				t.Errorf("AGT003 darwin docker: want Warning, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("AGT003: darwin docker group must fire Warning")
	}
}

func TestAGT003_AdminGroup_Warning(t *testing.T) {
	c := findCheck(t, "AGT003")
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{agentProcess("claude", []string{"admin"})},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT003" && f.IsFail() {
			found = true
		}
	}
	if !found {
		t.Fatal("AGT003: admin group must fire")
	}
}

func TestAGT003_SudoGroup_Linux_Critical(t *testing.T) {
	c := findCheck(t, "AGT003")
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{agentProcess("openclaw", []string{"sudo"})},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	var found bool
	for _, f := range findings {
		if f.CheckID == "AGT003" && f.IsFail() {
			found = true
			if f.Severity != model.SeverityCritical {
				t.Errorf("AGT003 linux sudo: want Critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("AGT003: linux sudo group must fire Critical")
	}
}

func TestAGT003_RegularGroups_Pass(t *testing.T) {
	c := findCheck(t, "AGT003")
	sigs := &model.Signals{
		Platform:  model.Platform{OS: "linux"},
		Processes: []model.ProcessFact{agentProcess("openclaw", []string{"users", "plugdev"})},
	}
	findings := c.Run(makeCtxWithCollector(sigs))
	for _, f := range findings {
		if f.CheckID == "AGT003" && f.IsFail() {
			t.Errorf("AGT003: should pass for regular groups, got %+v", f)
		}
	}
}

func TestAGT003_NoCollector_NotAssessed(t *testing.T) {
	c := findCheck(t, "AGT003")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("AGT003: want NotAssessed, got %+v", findings)
	}
}
