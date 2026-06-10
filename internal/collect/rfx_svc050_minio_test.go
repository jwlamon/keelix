package collect

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestRFX_SVC050_MinioParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC050")

	t.Run("default creds fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "minio_default.env"),
			parseMinioEnv,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseMinioEnv did not recognise fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC050" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC050: want failing finding for default creds; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("custom creds passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "minio_custom.env"),
			parseMinioEnv,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseMinioEnv did not recognise custom fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC050" && f.IsFail() {
				t.Errorf("SVC050: must NOT fire for custom creds; got %+v", f)
			}
		}
	})
}
