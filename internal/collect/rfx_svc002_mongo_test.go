package collect

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX_SVC002_MongoParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC002")

	t.Run("authorization absent fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "mongod_noauth.conf"),
			parseMongodConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseMongodConf did not recognise fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC002" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC002: want failing finding for absent authorization; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("authorization enabled passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "mongod_auth.conf"),
			parseMongodConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseMongodConf did not recognise safe fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC002" && f.IsFail() {
				t.Errorf("SVC002: must NOT fire for authorization=enabled; got %+v", f)
			}
		}
	})
}
