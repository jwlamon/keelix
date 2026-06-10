package supplychain

import (
	"github.com/jakelamon/keelix/internal/catalog"
	"github.com/jakelamon/keelix/internal/model"
)

// notAssessed returns a Finding with StatusNotAssessed for the given catalog ID.
func notAssessed(id string) model.Finding {
	f := catalog.Get(id).Finding()
	f.Status = model.StatusNotAssessed
	f.Detail = "no compose services to assess"
	return f
}
