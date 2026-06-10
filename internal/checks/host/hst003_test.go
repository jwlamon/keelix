package host_test

import (
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/host"
	"github.com/jakelamon/keelix/internal/model"
)

func makeHST003Context(passAuth, permitRoot, source, bindAddr string) *model.ScanContext {
	vals := map[string]string{
		"passwordauthentication": passAuth,
		"permitrootlogin":        permitRoot,
		"_source":                source,
	}
	sigs := &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{SchemaID: "sshd-effective", SchemaKnown: true, Values: vals},
		},
	}
	if bindAddr != "" {
		sigs.Sockets = []model.ListeningSocket{
			{Proto: "tcp", Bind: bindAddr, Port: 22},
		}
	}
	return &model.ScanContext{Collector: sigs}
}

func TestHST003_NilCollector_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{}
	fs := runCheck("HST003", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestHST003_AllConditions_Internet_Fires_Critical_Fatal(t *testing.T) {
	ctx := makeHST003Context("yes", "yes", "effective", "0.0.0.0")
	fs := runCheck("HST003", ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Passed {
		t.Fatal("expected failing finding")
	}
	if f.Severity != model.SeverityCritical {
		t.Fatalf("expected Critical, got %v", f.Severity)
	}
	if !f.Fatal {
		t.Fatal("expected Fatal=true for HST003")
	}
	if f.ExposureClass != model.ExposureInternet {
		t.Fatalf("expected ExposureInternet, got %v", f.ExposureClass)
	}
}

func TestHST003_StaticSource_DoesNotFire_Fatal(t *testing.T) {
	// Static source must not fire the fatal finding — gate requires _source=effective.
	ctx := makeHST003Context("yes", "yes", "static", "0.0.0.0")
	fs := runCheck("HST003", ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	// Either NotAssessed or a non-Fatal finding with ConfidenceMedium.
	if f.Fatal {
		t.Fatal("static source must not produce Fatal HST003")
	}
	if f.Status == model.StatusAssessed && f.Confidence != model.ConfidenceMedium {
		t.Fatalf("static source assessed finding should have ConfidenceMedium, got %v", f.Confidence)
	}
}

func TestHST003_LoopbackSocket_PassesOrNotAssessed(t *testing.T) {
	// When sshd listens only on loopback, HST003 should not fire as internet-exposed.
	ctx := makeHST003Context("yes", "yes", "effective", "127.0.0.1")
	fs := runCheck("HST003", ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].Fatal {
		t.Fatal("loopback-only sshd should not fire Fatal HST003")
	}
}

func TestHST003_NoSocket_NotAssessed(t *testing.T) {
	// No socket data means we cannot confirm a non-loopback bind.
	ctx := makeHST003Context("yes", "yes", "effective", "")
	fs := runCheck("HST003", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed with no socket data, got %+v", fs)
	}
}

func TestHST003_PasswordAuthNo_Passes(t *testing.T) {
	ctx := makeHST003Context("no", "yes", "effective", "0.0.0.0")
	fs := runCheck("HST003", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when passwordauth=no, got %+v", fs)
	}
}
