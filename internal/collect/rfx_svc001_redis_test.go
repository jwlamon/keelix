package collect

// TestRFX_SVC001_RedisParserFed is the MANDATORY parser-fed test for SVC001.
// It runs the real parseRedisConf parser (SLICE-D) over committed testdata
// fixtures and feeds the resulting ConfigFact to SVC001.Run() via the
// registered model.Check interface.
//
// Verifies:
//   - no-auth triad fixture (bind 0.0.0.0 + protected-mode no + no requirepass) fires
//   - safe fixture (bind 127.0.0.1 + requirepass set) does not fire

import (
	"path/filepath"
	"testing"

	_ "github.com/jwlamon/keelix/internal/checks/service"
	"github.com/jwlamon/keelix/internal/model"
)

// TestRFX_SVC001_MultiAddrLoopback verifies R3-5: a bind directive with multiple
// whitespace-separated tokens that are ALL loopback (127.0.0.1 ::1) must NOT
// fire SVC001 — the exact-string check "bind != 127.0.0.1" is wrong for this case.
func TestRFX_SVC001_MultiAddrLoopback(t *testing.T) {
	c := findRegisteredCheck(t, "SVC001")

	fact := collectConfigInternal(
		filepath.Join("testdata", "redis_multiaddr_loopback.conf"),
		parseRedisConf,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseRedisConf did not recognise fixture; values: %v", fact.Values)
	}
	// The bind value is "127.0.0.1 ::1" — all tokens are loopback.
	if fact.Values["bind"] != "127.0.0.1 ::1" {
		t.Fatalf("fixture bind=%q, want \"127.0.0.1 ::1\"", fact.Values["bind"])
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC001" && f.IsFail() {
			t.Errorf("SVC001: must NOT fire when all bind tokens are loopback (127.0.0.1 ::1); got %+v", f)
		}
	}
}

// TestRFX_SVC001_DefaultBindV7 verifies R4-1a: Redis 7 default "bind 127.0.0.1 -::1"
// uses the "-" optional-address prefix; the stripped token "::1" is loopback,
// so SVC001 must NOT fire on this stock Redis 7 config.
func TestRFX_SVC001_DefaultBindV7(t *testing.T) {
	c := findRegisteredCheck(t, "SVC001")

	fact := collectConfigInternal(
		filepath.Join("testdata", "redis_default_bind_v7.conf"),
		parseRedisConf,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseRedisConf did not recognise fixture; values: %v", fact.Values)
	}
	if fact.Values["bind"] != "127.0.0.1 -::1" {
		t.Fatalf("fixture bind=%q, want \"127.0.0.1 -::1\"", fact.Values["bind"])
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC001" && f.IsFail() {
			t.Errorf("SVC001: must NOT fire for Redis 7 default bind (127.0.0.1 -::1); got %+v", f)
		}
	}
}

// TestRFX_SVC001_NoBind_NoAuth verifies R4-1b: a Redis config with no bind
// directive listens on 0.0.0.0 by default; with no requirepass and
// protected-mode off this MUST fire SVC001.
func TestRFX_SVC001_NoBind_NoAuth(t *testing.T) {
	c := findRegisteredCheck(t, "SVC001")

	fact := collectConfigInternal(
		filepath.Join("testdata", "redis_nobind_noauth.conf"),
		parseRedisConf,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseRedisConf did not recognise fixture; values: %v", fact.Values)
	}
	if fact.Values["bind"] != "" {
		t.Fatalf("fixture bind=%q, want empty string (no bind directive)", fact.Values["bind"])
	}
	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC001" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC001: must fire when no bind directive (public 0.0.0.0 default), no auth; got %+v\nParsed values: %v", findings, fact.Values)
}

func TestRFX_SVC001_RedisParserFed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC001")

	t.Run("no-auth triad fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "redis_noauth_triad.conf"),
			parseRedisConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseRedisConf did not recognise fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC001" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC001: want failing finding for no-auth triad; got %+v\nParsed values: %v", findings, fact.Values)
	})

	t.Run("safe config does not fire", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "redis_safe.conf"),
			parseRedisConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseRedisConf did not recognise safe fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC001" && f.IsFail() {
				t.Errorf("SVC001: must NOT fire for safe config; got %+v", f)
			}
		}
	})
}
