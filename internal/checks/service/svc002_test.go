package service_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC002_NilCollector_NotAssessed(t *testing.T) {
	fs := runCheck("SVC002", &model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestSVC002_NoConfig_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{}}
	fs := runCheck("SVC002", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed with no mongod-conf, got %+v", fs)
	}
}

func TestSVC002_AuthDisabled_Fires(t *testing.T) {
	// The parser emits "" for disabled/absent (not "disabled") — see parseMongodConf.
	// Using "" here reflects what the check actually receives from the parser pipeline.
	ctx := &model.ScanContext{
		Collector: makeSigs("mongod-conf", map[string]string{
			"security.authorization": "",
		}),
	}
	fs := runCheck("SVC002", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for not-enabled auth, got %+v", fs)
	}
	if fs[0].Metadata["port"] != "27017" {
		t.Errorf("expected Metadata[port]=27017, got %q", fs[0].Metadata["port"])
	}
}

func TestSVC002_AuthAbsent_Fires(t *testing.T) {
	// Key absent means no authorization config = not enabled.
	ctx := &model.ScanContext{
		Collector: makeSigs("mongod-conf", map[string]string{}),
	}
	fs := runCheck("SVC002", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding when key absent, got %+v", fs)
	}
}

func TestSVC002_AuthEnabled_Passes(t *testing.T) {
	// In production the parser emits "enabled" which gets redacted to "[secret]";
	// any non-empty value is treated as "authorization configured" → pass.
	ctx := &model.ScanContext{
		Collector: makeSigs("mongod-conf", map[string]string{
			"security.authorization": "enabled",
		}),
	}
	fs := runCheck("SVC002", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for enabled, got %+v", fs)
	}
}

func TestSVC002_AuthRedacted_Passes(t *testing.T) {
	// Simulates the post-redaction value: parseMongodConf emits "enabled" which
	// collectConfigInternal redacts to "[secret]" (classOf treats the key as a
	// credential path). The check must not fire for any non-empty value.
	ctx := &model.ScanContext{
		Collector: makeSigs("mongod-conf", map[string]string{
			"security.authorization": "[secret]",
		}),
	}
	fs := runCheck("SVC002", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for redacted (non-empty) auth value, got %+v", fs)
	}
}
