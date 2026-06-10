package service

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestNotAssessed(t *testing.T) {
	// SVC001 must be in the catalog (added by Task E2a-1).
	f := notAssessed("SVC001")
	if f.Status != model.StatusNotAssessed {
		t.Fatalf("expected StatusNotAssessed, got %v", f.Status)
	}
	if f.CheckID != "SVC001" {
		t.Fatalf("expected CheckID SVC001, got %q", f.CheckID)
	}
}

func TestConfigBySchema(t *testing.T) {
	sigs := &model.Signals{
		Configs: []model.ConfigFact{
			{SchemaID: "redis-conf", SchemaKnown: true, Values: map[string]string{"requirepass.present": "false"}},
			{SchemaID: "other", SchemaKnown: false},
		},
	}
	cf, ok := configBySchema(sigs, "redis-conf")
	if !ok {
		t.Fatal("expected ok=true for redis-conf")
	}
	if cf.Values["requirepass.present"] != "false" {
		t.Fatalf("unexpected value: %q", cf.Values["requirepass.present"])
	}
	_, ok2 := configBySchema(sigs, "other")
	if ok2 {
		t.Fatal("SchemaKnown=false should not match")
	}
	_, ok3 := configBySchema(nil, "redis-conf")
	if ok3 {
		t.Fatal("nil Signals should return ok=false")
	}
}
