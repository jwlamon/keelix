package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectServiceConfigs_AllowlistCleanup(t *testing.T) {
	// Record the baseline allowlist length before any call.
	before := len(allowlist)
	dir := t.TempDir()
	f := filepath.Join(dir, "redis.conf")
	if err := os.WriteFile(f, []byte("requirepass mypassword\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		ServiceConfigs: []ConfigCandidate{
			{Path: f, SchemaID: "docker-daemon"}, // docker-daemon parser is registered in parserForSchemaID
		},
	}
	_ = collectServiceConfigs(opts)
	after := len(allowlist)
	if before != after {
		t.Errorf("allowlist leaked: before=%d after=%d", before, after)
	}
}
