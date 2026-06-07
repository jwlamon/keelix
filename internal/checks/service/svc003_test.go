package service_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestSVC003_NilCollector_NotAssessed(t *testing.T) {
	fs := runCheck("SVC003", &model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestSVC003_NoConfig_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{}}
	fs := runCheck("SVC003", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed with no pg-hba, got %+v", fs)
	}
}

func TestSVC003_TrustNonlocal_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("pg-hba", map[string]string{"trust.nonlocal": "true"}),
	}
	fs := runCheck("SVC003", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for trust.nonlocal=true, got %+v", fs)
	}
	if fs[0].Metadata["port"] != "5432" {
		t.Errorf("expected Metadata[port]=5432, got %q", fs[0].Metadata["port"])
	}
}

func TestSVC003_TrustNonlocalFalse_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("pg-hba", map[string]string{"trust.nonlocal": "false"}),
	}
	fs := runCheck("SVC003", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for trust.nonlocal=false, got %+v", fs)
	}
}
