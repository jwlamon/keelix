package service_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestSVC050_NilCollector_NotAssessed(t *testing.T) {
	fs := runCheck("SVC050", &model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestSVC050_DefaultCreds_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("minio-env", map[string]string{"root-creds.default": "true"}),
	}
	fs := runCheck("SVC050", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for default creds, got %+v", fs)
	}
	if fs[0].Metadata["port"] != "9000" {
		t.Errorf("expected Metadata[port]=9000, got %q", fs[0].Metadata["port"])
	}
}

func TestSVC050_CustomCreds_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("minio-env", map[string]string{"root-creds.default": "false"}),
	}
	fs := runCheck("SVC050", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for custom creds, got %+v", fs)
	}
}

func TestSVC050_KeyAbsent_Passes(t *testing.T) {
	// If the parser couldn't determine default status, it does not emit "true".
	ctx := &model.ScanContext{
		Collector: makeSigs("minio-env", map[string]string{}),
	}
	fs := runCheck("SVC050", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when root-creds.default key absent, got %+v", fs)
	}
}
