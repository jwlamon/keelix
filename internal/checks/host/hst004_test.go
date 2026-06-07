package host_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

func TestHST004_WeakMaxAuthTries_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"maxauthtries": "6",
			"_source":      "effective",
		}),
	}
	fs := runCheck("HST004", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for maxauthtries=6, got %+v", fs)
	}
}

func TestHST004_WeakLoginGracetime_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"maxauthtries":   "3",
			"logingracetime": "120",
			"_source":        "effective",
		}),
	}
	fs := runCheck("HST004", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for logingracetime=120, got %+v", fs)
	}
}

func TestHST004_X11Forwarding_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"x11forwarding": "yes",
			"_source":       "effective",
		}),
	}
	fs := runCheck("HST004", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for x11forwarding=yes, got %+v", fs)
	}
}

func TestHST004_PermitEmptyPasswords_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"permitemptypasswords": "yes",
			"_source":              "effective",
		}),
	}
	fs := runCheck("HST004", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for permitemptypasswords=yes, got %+v", fs)
	}
}

func TestHST004_AllGood_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"maxauthtries":         "3",
			"logingracetime":       "30",
			"x11forwarding":        "no",
			"permitemptypasswords": "no",
			"_source":              "effective",
		}),
	}
	fs := runCheck("HST004", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for good sshd params, got %+v", fs)
	}
}

func TestHST005_NoFail2ban_PasswordAuthOn_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{
				{SchemaID: "sshd-effective", SchemaKnown: true, Values: map[string]string{
					"passwordauthentication": "yes",
					"_source":                "effective",
				}},
			},
			Processes: []model.ProcessFact{},
		},
	}
	fs := runCheck("HST005", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for no fail2ban + password auth on, got %+v", fs)
	}
}

func TestHST005_Fail2banRunning_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{
				{SchemaID: "sshd-effective", SchemaKnown: true, Values: map[string]string{
					"passwordauthentication": "yes",
					"_source":                "effective",
				}},
			},
			Processes: []model.ProcessFact{{Comm: "fail2ban-server"}},
		},
	}
	fs := runCheck("HST005", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when fail2ban running, got %+v", fs)
	}
}

func TestHST005_NilCollector_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{}
	fs := runCheck("HST005", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}
