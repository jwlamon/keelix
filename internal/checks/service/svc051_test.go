package service_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC051_NilCollector_NotAssessed(t *testing.T) {
	fs := runCheck("SVC051", &model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestSVC051_AllowAnonymous_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("mosquitto-conf", map[string]string{"allow_anonymous": "true"}),
	}
	fs := runCheck("SVC051", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for allow_anonymous=true, got %+v", fs)
	}
	if fs[0].Metadata["port"] != "1883" {
		t.Errorf("expected Metadata[port]=1883, got %q", fs[0].Metadata["port"])
	}
}

func TestSVC051_AllowAnonymousFalse_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("mosquitto-conf", map[string]string{"allow_anonymous": "false"}),
	}
	fs := runCheck("SVC051", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for allow_anonymous=false, got %+v", fs)
	}
}

func TestSVC051_KeyAbsent_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSigs("mosquitto-conf", map[string]string{}),
	}
	fs := runCheck("SVC051", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when allow_anonymous key absent (defaults to false), got %+v", fs)
	}
}
