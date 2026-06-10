// Package service implements GroupService checks (SVC001–SVC060+).
// All checks are pure functions of *model.ScanContext: no I/O, no globals.
package service

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

// notAssessed returns a Finding for id with StatusNotAssessed.
func notAssessed(id string) model.Finding {
	f := catalog.Get(id).Finding()
	f.Status = model.StatusNotAssessed
	f.Detail = "service config not discovered; bind-mount the config file and re-run with --collect"
	return f
}

// configBySchema returns the first ConfigFact in sigs.Configs whose SchemaID
// matches id and SchemaKnown is true.
func configBySchema(sigs *model.Signals, id string) (model.ConfigFact, bool) {
	if sigs == nil {
		return model.ConfigFact{}, false
	}
	for _, c := range sigs.Configs {
		if c.SchemaID == id && c.SchemaKnown {
			return c, true
		}
	}
	return model.ConfigFact{}, false
}
