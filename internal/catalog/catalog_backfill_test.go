package catalog

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestBaseImpactDefaultsFromSeverity(t *testing.T) {
	cases := map[string]float64{
		"EXP002": 5.0, // Warning
		"EXP003": 2.0, // Info
		"HRD001": 9.0, // Critical (non-fatal)
		"SUP001": 2.0, // Info
	}
	for id, want := range cases {
		got := Get(id).BaseImpact
		if got != want {
			t.Errorf("%s BaseImpact = %v, want %v (severity %s)", id, got, want, Get(id).Severity)
		}
	}
}

func TestFatalEntriesAreMarked(t *testing.T) {
	for _, id := range []string{"EXP001", "FW001"} {
		e := Get(id)
		if !e.Fatal {
			t.Errorf("%s: expected Fatal=true", id)
		}
		if e.BaseImpact < 9 || e.BaseImpact > 10 {
			t.Errorf("%s: fatal BaseImpact = %v, want 9-10", id, e.BaseImpact)
		}
		if e.Severity != model.SeverityCritical {
			t.Errorf("%s: expected fatal entry to be Critical, got %s", id, e.Severity)
		}
	}
}

func TestNonFatalEntriesAreNotFatal(t *testing.T) {
	// Rule: every SeverityCritical SVC/FW config check is Fatal (R2-2, R4-3).
	// SF-3: SUP003 is intentionally NOT in this list — its Fatal escalation is
	// conditional (score.applyKEVFatal promotes it only at routable exposure).
	fatal := map[string]bool{
		"EXP001": true,
		"FW001":  true,
		"FW005":  true, // Docker daemon API over TCP: fatal via fatalImpact map
		"FW006":  true, // k3s/kubelet anon auth: fatal via fatalImpact map (R2-2)
		"AGT002": true, // lethal-trifecta: fatal via fatalImpact map (B.5)
		"AGT006": true, // non-loopback control surface: fatal via fatalImpact map (B.5)
		"MCP004": true, // HTTP/SSE MCP non-loopback without auth: fatal via fatalImpact map (B.4)
		"HST003": true, // SSH internet-exposed trifecta: fatal via fatalImpact map
		"SVC001": true, // Redis no-auth triad: fatal via fatalImpact map (A.3)
		"SVC002": true, // MongoDB no-auth: fatal via fatalImpact map (A.3)
		"SVC003": true, // PostgreSQL trust auth: fatal via fatalImpact map (A.3)
		"SVC004": true, // Elasticsearch X-Pack security disabled: fatal via fatalImpact map (R2-2)
		"SVC010": true, // *arr application no-auth: fatal via fatalImpact map (R4-3)
		"SVC030": true, // Vaultwarden admin token absent or weak: fatal via fatalImpact map (R2-2)
		"SVC032": true, // Jenkins security disabled: fatal via fatalImpact map (R2-2)
		"SVC050": true, // MinIO default root credentials: fatal via fatalImpact map (R2-2)
		"SVC060": true, // Traefik api.insecure=true: fatal via fatalImpact map (R4-3)
		// SUP003 deliberately absent (SF-3): catalog emits Fatal=false; applyKEVFatal
		// conditionally escalates at routable exposure only.
	}
	for _, e := range All() {
		if !fatal[e.ID] && e.Fatal {
			t.Errorf("%s: unexpectedly marked Fatal", e.ID)
		}
	}
}
