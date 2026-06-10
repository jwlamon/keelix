package host_test

import (
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/host"
	"github.com/jakelamon/keelix/internal/model"
)

func linuxSigs(pkg model.PackageState) *model.Signals {
	return &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Packages: pkg,
	}
}

func TestHST010_PendingUpdates_Fires(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{SecurityUpdatesPending: 3})}
	fs := runCheck("HST010", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for pending updates, got %+v", fs)
	}
}

func TestHST010_PendingUpdates_DistroEOL_Critical(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{
		SecurityUpdatesPending: 3,
		DistroEOL:              true,
	})}
	fs := runCheck("HST010", ctx)
	if len(fs) != 1 || fs[0].Severity != model.SeverityCritical {
		t.Fatalf("expected Critical when DistroEOL, got %+v", fs)
	}
}

func TestHST010_PendingUpdates_Over20_Critical(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{SecurityUpdatesPending: 25})}
	fs := runCheck("HST010", ctx)
	if len(fs) != 1 || fs[0].Severity != model.SeverityCritical {
		t.Fatalf("expected Critical for >20 updates, got %+v", fs)
	}
}

func TestHST010_NoPending_Passes(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{SecurityUpdatesPending: 0})}
	fs := runCheck("HST010", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for no pending updates, got %+v", fs)
	}
}

func TestHST010_Darwin_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}}}
	fs := runCheck("HST010", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed on darwin, got %+v", fs)
	}
}

func TestHST011_DistroEOL_Fires(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{DistroEOL: true})}
	fs := runCheck("HST011", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for DistroEOL, got %+v", fs)
	}
}

func TestHST011_NotEOL_Passes(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{DistroEOL: false})}
	fs := runCheck("HST011", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when not EOL, got %+v", fs)
	}
}

func TestHST012_RebootRequired_Fires(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{RebootRequired: true})}
	fs := runCheck("HST012", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for RebootRequired, got %+v", fs)
	}
}

func TestHST012_NoReboot_Passes(t *testing.T) {
	ctx := &model.ScanContext{Collector: linuxSigs(model.PackageState{RebootRequired: false})}
	fs := runCheck("HST012", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when no reboot needed, got %+v", fs)
	}
}

func TestHST013_UnattendedUpgradesDisabled_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{
				{SchemaID: "apt-periodic", SchemaKnown: true, Values: map[string]string{
					"unattended_upgrade": "0",
				}},
			},
		},
	}
	fs := runCheck("HST013", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for unattended_upgrade=0, got %+v", fs)
	}
}

func TestHST013_UnattendedUpgradesEnabled_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{
				{SchemaID: "apt-periodic", SchemaKnown: true, Values: map[string]string{
					"unattended_upgrade": "1",
				}},
			},
		},
	}
	fs := runCheck("HST013", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when unattended_upgrade=1, got %+v", fs)
	}
}

func TestHST013_Darwin_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}}}
	fs := runCheck("HST013", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed on darwin for HST013, got %+v", fs)
	}
}
