package service_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC004_NilCollector_NotAssessed(t *testing.T) {
	fs := runCheck("SVC004", &model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestSVC004_SecurityFalse_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("elasticsearch-yml", map[string]string{
			"xpack.security.enabled": "false",
		}),
	}
	fs := runCheck("SVC004", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for xpack.security.enabled=false, got %+v", fs)
	}
	if fs[0].Metadata["port"] != "9200" {
		t.Errorf("expected Metadata[port]=9200, got %q", fs[0].Metadata["port"])
	}
}

func TestSVC004_SecurityAbsent_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("elasticsearch-yml", map[string]string{}),
	}
	fs := runCheck("SVC004", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding when key absent, got %+v", fs)
	}
}

func TestSVC004_SecurityTrue_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("elasticsearch-yml", map[string]string{
			"xpack.security.enabled": "true",
		}),
	}
	fs := runCheck("SVC004", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for xpack.security.enabled=true, got %+v", fs)
	}
}
