//go:build !integration

package service_test

import (
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/firewall"
	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestServiceChecks_NilCollector_NotAssessed(t *testing.T) {
	// All SVC* checks must return NotAssessed when Collector is nil.
	svcIDs := []string{
		"SVC001", "SVC002", "SVC003", "SVC004",
		"SVC010", "SVC011", "SVC020", "SVC021",
		"SVC030", "SVC031", "SVC032",
		"SVC040", "SVC041",
		"SVC050", "SVC051", "SVC052",
		"SVC060",
	}
	ctx := &model.ScanContext{} // nil Collector

	for _, id := range svcIDs {
		id := id
		t.Run(id+"_nil_collector", func(t *testing.T) {
			c := findSvcCheck(t, id)
			fs := c.Run(ctx)
			if len(fs) == 0 {
				t.Fatalf("%s: returned no findings", id)
			}
			for _, f := range fs {
				if f.Status != model.StatusNotAssessed {
					t.Errorf("%s: Status = %v, want NotAssessed (nil Collector)", id, f.Status)
				}
			}
		})
	}
}

func TestLinuxOnlyChecks_Darwin_NotAssessed(t *testing.T) {
	// FW005 and FW006 must return NotAssessed on darwin.
	linuxOnlyIDs := []string{"FW005", "FW006"}
	darwinCtx := &model.ScanContext{
		Collector: &model.Signals{Platform: model.Platform{OS: "darwin"}},
	}
	for _, id := range linuxOnlyIDs {
		id := id
		t.Run(id+"_darwin_notAssessed", func(t *testing.T) {
			c := findSvcCheck(t, id)
			fs := c.Run(darwinCtx)
			if len(fs) == 0 {
				t.Fatalf("%s: returned no findings", id)
			}
			found := false
			for _, f := range fs {
				if f.Status == model.StatusNotAssessed {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: expected StatusNotAssessed on darwin, got: %+v", id, fs)
			}
		})
	}
}

func findSvcCheck(t *testing.T, id string) model.Check {
	t.Helper()
	for _, c := range model.Registered() {
		if c.ID() == id {
			return c
		}
	}
	t.Fatalf("check %s not registered", id)
	return nil
}
