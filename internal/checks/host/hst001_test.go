package host_test

import (
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/host"
	"github.com/jwlamon/keelix/internal/model"
)

func makeSSHDEffective(vals map[string]string) *model.Signals {
	return &model.Signals{
		Platform: model.Platform{OS: "linux"},
		Configs: []model.ConfigFact{
			{
				SchemaID:    "sshd-effective",
				SchemaKnown: true,
				Values:      vals,
			},
		},
	}
}

func runCheck(id string, ctx *model.ScanContext) []model.Finding {
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c.Run(ctx)
		}
	}
	panic("check not registered: " + id)
}

func TestHST001_NilCollector(t *testing.T) {
	ctx := &model.ScanContext{}
	fs := runCheck("HST001", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed with nil Collector, got %+v", fs)
	}
}

func TestHST001_NoConfig(t *testing.T) {
	ctx := &model.ScanContext{Collector: &model.Signals{Platform: model.Platform{OS: "linux"}}}
	fs := runCheck("HST001", ctx)
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Fatalf("expected NotAssessed with no sshd config, got %+v", fs)
	}
}

func TestHST001_PasswordAuthYes_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"passwordauthentication": "yes",
			"_source":                "effective",
		}),
	}
	fs := runCheck("HST001", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for passwordauthentication=yes, got %+v", fs)
	}
	if fs[0].CheckID != "HST001" {
		t.Fatalf("wrong CheckID: %q", fs[0].CheckID)
	}
}

func TestHST001_PasswordAuthNo_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"passwordauthentication": "no",
			"_source":                "effective",
		}),
	}
	fs := runCheck("HST001", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for passwordauthentication=no, got %+v", fs)
	}
}

func TestHST001_MissingKey_DefaultYes_Fires(t *testing.T) {
	// SSH default for PasswordAuthentication is yes when key absent.
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{"_source": "static"}),
	}
	fs := runCheck("HST001", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding when key absent (default yes), got %+v", fs)
	}
}

func TestHST002_RootLoginYes_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"permitrootlogin": "yes",
			"_source":         "effective",
		}),
	}
	fs := runCheck("HST002", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for permitrootlogin=yes, got %+v", fs)
	}
}

func TestHST002_ProhibitPassword_Fires(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"permitrootlogin": "prohibit-password",
			"_source":         "effective",
		}),
	}
	fs := runCheck("HST002", ctx)
	if len(fs) != 1 || fs[0].Passed {
		t.Fatalf("expected failing finding for prohibit-password, got %+v", fs)
	}
}

func TestHST002_No_Passes(t *testing.T) {
	ctx := &model.ScanContext{
		Collector: makeSSHDEffective(map[string]string{
			"permitrootlogin": "no",
			"_source":         "effective",
		}),
	}
	fs := runCheck("HST002", ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Fatalf("expected pass for permitrootlogin=no, got %+v", fs)
	}
}
