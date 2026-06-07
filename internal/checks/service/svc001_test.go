package service_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

func runCheck(id string, ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c.Run(ctx)
		}
	}
	panic("check not registered: " + id)
}

func makeSigs(schemaID string, vals map[string]string) *model.Signals {
	return &model.Signals{
		Configs: []model.ConfigFact{
			{SchemaID: schemaID, SchemaKnown: true, Values: vals},
		},
	}
}

func TestSVC001_NilCollector_NotAssessed(t *testing.T) {
	fs := runCheck("SVC001", &model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestSVC001_NoConfig_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{}}
	fs := runCheck("SVC001", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed with no redis-conf, got %+v", fs)
	}
}

func TestSVC001_Triad_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("redis-conf", map[string]string{
			"requirepass.present": "false",
			"protected-mode":      "no",
			"bind":                "0.0.0.0",
		}),
	}
	fs := runCheck("SVC001", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for no-auth triad, got %+v", fs)
	}
	if fs[0].CheckID != "SVC001" {
		t.Errorf("expected CheckID SVC001, got %q", fs[0].CheckID)
	}
	if fs[0].Metadata["port"] != "6379" {
		t.Errorf("expected Metadata[port]=6379, got %q", fs[0].Metadata["port"])
	}
}

func TestSVC001_RequirepassPresent_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("redis-conf", map[string]string{
			"requirepass.present": "true",
			"protected-mode":      "no",
			"bind":                "0.0.0.0",
		}),
	}
	fs := runCheck("SVC001", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when requirepass present, got %+v", fs)
	}
}

func TestSVC001_ProtectedModeOn_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("redis-conf", map[string]string{
			"requirepass.present": "false",
			"protected-mode":      "yes",
			"bind":                "0.0.0.0",
		}),
	}
	fs := runCheck("SVC001", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when protected-mode yes, got %+v", fs)
	}
}

func TestSVC001_BindLoopback_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("redis-conf", map[string]string{
			"requirepass.present": "false",
			"protected-mode":      "no",
			"bind":                "127.0.0.1",
		}),
	}
	fs := runCheck("SVC001", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when bind=127.0.0.1, got %+v", fs)
	}
}
