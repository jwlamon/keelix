package collect

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

func TestRFX_SVC051_MosquittoParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC051")

	t.Run("allow_anonymous true fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "mosquitto_anon.conf"),
			parseMosquittoConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseMosquittoConf did not recognise fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC051" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC051: want failing finding for allow_anonymous; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("allow_anonymous false passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "mosquitto_auth.conf"),
			parseMosquittoConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseMosquittoConf did not recognise safe fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC051" && f.IsFail() {
				t.Errorf("SVC051: must NOT fire for allow_anonymous=false; got %+v", f)
			}
		}
	})
}
