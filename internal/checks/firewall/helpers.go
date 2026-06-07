package firewall

import (
	"github.com/jwlamon/keelix/internal/catalog"
	"github.com/jwlamon/keelix/internal/model"
)

// notAssessed returns a Finding with StatusNotAssessed for the given catalog ID.
func notAssessed(id string) model.Finding {
	f := catalog.Get(id).Finding()
	f.Status = model.StatusNotAssessed
	f.Detail = "inside-out collector data unavailable for this check; run with --collect"
	return f
}

// notAssessedNoServices returns a Finding with StatusNotAssessed for a
// compose-only check when the stack has no services to assess.
func notAssessedNoServices(id string) model.Finding {
	f := catalog.Get(id).Finding()
	f.Status = model.StatusNotAssessed
	f.Detail = "no compose services to assess"
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
