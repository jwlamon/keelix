package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jwlamon/keelix/internal/engine"
	"github.com/jwlamon/keelix/internal/model"

	_ "github.com/jwlamon/keelix/internal/checks/all"
)

// Build a tiny stack on disk with a literal secret env value and assert the
// engine's Result never echoes that value in any finding field.
func TestScanRedactsLiteralSecret(t *testing.T) {
	dir := t.TempDir()
	compose := `services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    ports:
      - "5432:5432"
`
	env := "POSTGRES_PASSWORD=supersecretLiteralPW\n"
	composePath := filepath.Join(dir, "docker-compose.yml")
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(composePath, []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := engine.Scan(context.Background(), engine.Input{
		ComposePath: composePath,
		EnvPath:     envPath,
		Options:     model.ScanOptions{NoProbe: true},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	for _, f := range r.Findings {
		blob := strings.Join([]string{
			f.Title, f.Detail, f.Evidence, f.Resource,
			f.Fix.Summary, f.Fix.Diff, strings.Join(f.Fix.Commands, " "),
		}, " ")
		if strings.Contains(blob, "supersecretLiteralPW") {
			t.Fatalf("finding %s leaked the literal secret: %q", f.CheckID, blob)
		}
	}
}
