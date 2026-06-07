package host_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

func TestHST030_NoFirewall_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Firewall: model.FirewallState{Backend: "none"},
		},
	}
	fs := runCheck("HST030", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for no firewall, got %+v", fs)
	}
}

func TestHST030_NotDefaultDeny_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Firewall: model.FirewallState{Backend: "ufw", DefaultInbound: "allow"},
		},
	}
	fs := runCheck("HST030", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for allow default inbound, got %+v", fs)
	}
}

func TestHST030_DefaultDeny_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Firewall: model.FirewallState{Backend: "ufw", DefaultInbound: "deny"},
		},
	}
	fs := runCheck("HST030", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for default-deny firewall, got %+v", fs)
	}
}

func TestHST030_DefaultDrop_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Firewall: model.FirewallState{Backend: "nftables", DefaultInbound: "drop"},
		},
	}
	fs := runCheck("HST030", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for default-drop firewall, got %+v", fs)
	}
}

func TestHST030_Darwin_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}}}
	fs := runCheck("HST030", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed on darwin, got %+v", fs)
	}
}

func TestHST040_WeakASLR_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{{
				SchemaID:    "sysctl",
				SchemaKnown: true,
				Values:      map[string]string{"kernel.randomize_va_space": "0"},
			}},
		},
	}
	fs := runCheck("HST040", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for ASLR disabled, got %+v", fs)
	}
}

func TestHST040_AllGood_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{{
				SchemaID:    "sysctl",
				SchemaKnown: true,
				Values: map[string]string{
					"kernel.randomize_va_space": "2",
					"kernel.kptr_restrict":      "1",
					"kernel.dmesg_restrict":     "1",
					"kernel.yama.ptrace_scope":  "1",
					"fs.suid_dumpable":          "0",
				},
			}},
		},
	}
	fs := runCheck("HST040", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for good sysctl values, got %+v", fs)
	}
}

func TestHST040_Darwin_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}}}
	fs := runCheck("HST040", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed on darwin for HST040, got %+v", fs)
	}
}

func TestHST041_NilCollector_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{}
	fs := runCheck("HST041", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}
