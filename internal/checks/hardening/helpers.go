package hardening

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

// notAssessed returns a Finding with StatusNotAssessed for the given catalog ID.
// Used when inside-out collector data is unavailable.
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

// fileByPath returns the FileFact for path if present in sigs.Files.
func fileByPath(sigs *model.Signals, path string) (model.FileFact, bool) {
	if sigs == nil {
		return model.FileFact{}, false
	}
	for _, ff := range sigs.Files {
		if ff.Path == path {
			return ff, true
		}
	}
	return model.FileFact{}, false
}
