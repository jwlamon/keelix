package host_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

func sudoersConfig(nopasswdPresent string) model.ConfigFact {
	return model.ConfigFact{
		SchemaID:    "accounts-sudoers",
		SchemaKnown: true,
		Values:      map[string]string{"nopasswd.present": nopasswdPresent},
	}
}

func TestHST020_NopasswdPresent_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{sudoersConfig("true")},
		},
	}
	fs := runCheck("HST020", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for NOPASSWD in sudoers, got %+v", fs)
	}
}

func TestHST020_NoNopasswd_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs:  []model.ConfigFact{sudoersConfig("false")},
		},
	}
	fs := runCheck("HST020", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for no NOPASSWD, got %+v", fs)
	}
}

func TestHST020_NilCollector_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{}
	fs := runCheck("HST020", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed, got %+v", fs)
	}
}

func TestHST021_DuplicateUID0_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{{
				SchemaID:    "accounts-passwd",
				SchemaKnown: true,
				Values: map[string]string{
					"uid0.accounts": "root:0,toor:0",
				},
			}},
		},
	}
	fs := runCheck("HST021", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for multiple UID0, got %+v", fs)
	}
}

func TestHST021_OnlyRoot_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Configs: []model.ConfigFact{{
				SchemaID:    "accounts-passwd",
				SchemaKnown: true,
				Values:      map[string]string{"uid0.accounts": "root:0"},
			}},
		},
	}
	fs := runCheck("HST021", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for only root as UID0, got %+v", fs)
	}
}

func TestHST022_EmptyPassword_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform:  model.Platform{OS: "linux"},
			Privilege: model.Privilege{Root: true},
			Configs: []model.ConfigFact{{
				SchemaID:    "accounts-shadow",
				SchemaKnown: true,
				Values:      map[string]string{"empty.password.accounts": "baduser"},
			}},
		},
	}
	fs := runCheck("HST022", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for empty password account, got %+v", fs)
	}
}

func TestHST022_NoEmptyPasswords_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform:  model.Platform{OS: "linux"},
			Privilege: model.Privilege{Root: true},
			Configs: []model.ConfigFact{{
				SchemaID:    "accounts-shadow",
				SchemaKnown: true,
				Values:      map[string]string{"empty.password.accounts": ""},
			}},
		},
	}
	fs := runCheck("HST022", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass when no empty passwords, got %+v", fs)
	}
}

func TestHST022_NoShadowConfig_NotAssessed(t *testing.T) {
	// Without shadow config, check is NotAssessed (shadow unreadable).
	ctx := &model.ScanContext{
		Collector: &model.Signals{Platform: model.Platform{OS: "linux"}},
	}
	fs := runCheck("HST022", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed without shadow config, got %+v", fs)
	}
}

func TestHST023_ShadowWorldReadable_Fires(t *testing.T) {
	// 0644: other-read bit set → fires under 0o077 mask.
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/etc/shadow", Exists: true, Mode: "0644"},
			},
		},
	}
	fs := runCheck("HST023", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for world-readable shadow, got %+v", fs)
	}
}

func TestHST023_ShadowGroupReadable_Fires(t *testing.T) {
	// 0640: group-read bit set — fires under the 0o077 mask (group OR world).
	// Many distros use 0640 with root:shadow, but the spec mandates root-only (0600).
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/etc/shadow", Exists: true, Mode: "0640"},
			},
		},
	}
	fs := runCheck("HST023", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for group-readable shadow (0640), got %+v", fs)
	}
}

func TestHST023_ShadowProperMode_Passes(t *testing.T) {
	// 0600: root-only — no group or world bits set; passes under 0o077 mask.
	ctx := &model.ScanContext{
		Collector: &model.Signals{
			Platform: model.Platform{OS: "linux"},
			Files: []model.FileFact{
				{Path: "/etc/shadow", Exists: true, Mode: "0600"},
			},
		},
	}
	fs := runCheck("HST023", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for 0600 shadow (root-only), got %+v", fs)
	}
}

func TestHST023_NoFileFact_NotAssessed(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: &model.Signals{Platform: model.Platform{OS: "linux"}},
	}
	fs := runCheck("HST023", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed without shadow file fact, got %+v", fs)
	}
}
