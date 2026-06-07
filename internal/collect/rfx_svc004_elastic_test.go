package collect

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

func TestRFX_SVC004_ElasticParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC004")

	t.Run("security disabled fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "elasticsearch_nosec.yml"),
			parseElasticsearchYml,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseElasticsearchYml did not recognise fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC004" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC004: want failing finding for security disabled; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("security enabled passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "elasticsearch_sec.yml"),
			parseElasticsearchYml,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseElasticsearchYml did not recognise safe fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC004" && f.IsFail() {
				t.Errorf("SVC004: must NOT fire for security=true; got %+v", f)
			}
		}
	})
}
