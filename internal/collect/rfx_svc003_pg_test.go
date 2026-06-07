package collect

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

func TestRFX_SVC003_PgHbaParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC003")

	t.Run("trust for non-local fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "pg_hba_trust.conf"),
			parsePgHba,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parsePgHba did not recognise fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC003" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC003: want failing finding for trust; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("scram-sha-256 config passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "pg_hba_safe.conf"),
			parsePgHba,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parsePgHba did not recognise safe fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC003" && f.IsFail() {
				t.Errorf("SVC003: must NOT fire for scram-sha-256; got %+v", f)
			}
		}
	})
}
