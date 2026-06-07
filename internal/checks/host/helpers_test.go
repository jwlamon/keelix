package host

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestNotAssessed(t *testing.T) {
	// HST001 must be in the catalog (added by SLICE-B) before this runs.
	f := notAssessed("HST001")
	if f.Status != model.StatusNotAssessed {
		t.Fatalf("expected StatusNotAssessed, got %v", f.Status)
	}
	if f.CheckID != "HST001" {
		t.Fatalf("expected CheckID HST001, got %q", f.CheckID)
	}
}

func TestConfigBySchema(t *testing.T) {
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{SchemaID: "sshd-effective", SchemaKnown: true, Values: map[string]string{"k": "v"}},
			{SchemaID: "other", SchemaKnown: false},
		},
	}
	cf, ok := configBySchema(sigs, "sshd-effective")
	if !ok {
		t.Fatal("expected ok=true for sshd-effective")
	}
	if cf.Values["k"] != "v" {
		t.Fatalf("unexpected value: %q", cf.Values["k"])
	}
	_, ok2 := configBySchema(sigs, "other")
	if ok2 {
		t.Fatal("SchemaKnown=false should not match")
	}
	_, ok3 := configBySchema(nil, "sshd-effective")
	if ok3 {
		t.Fatal("nil Signals should return ok=false")
	}
}

func TestFileByPath(t *testing.T) {
	sigs := &model.Signals{
		Files: []model.FileFact{
			{Path: "/etc/shadow", Exists: true, Mode: "0640"},
		},
	}
	ff, ok := fileByPath(sigs, "/etc/shadow")
	if !ok || ff.Mode != "0640" {
		t.Fatalf("expected shadow fact, got ok=%v mode=%q", ok, ff.Mode)
	}
	_, ok2 := fileByPath(sigs, "/etc/passwd")
	if ok2 {
		t.Fatal("missing path should return ok=false")
	}
}

func TestExposureFromBind(t *testing.T) {
	cases := []struct {
		bind string
		want model.ExposureClass
	}{
		{"127.0.0.1", model.ExposureLocalhost},
		{"::1", model.ExposureLocalhost},
		{"0.0.0.0", model.ExposureInternet},
		{"::", model.ExposureInternet},
		{"10.0.0.1", model.ExposureLAN},
		{"192.168.1.1", model.ExposureLAN},
	}
	for _, tc := range cases {
		got := exposureFromBind(tc.bind)
		if got != tc.want {
			t.Errorf("exposureFromBind(%q) = %v, want %v", tc.bind, got, tc.want)
		}
	}
}
