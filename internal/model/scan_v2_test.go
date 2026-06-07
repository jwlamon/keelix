package model

import (
	"encoding/json"
	"testing"
)

func TestScanContextHasCollector(t *testing.T) {
	// Compiles only once model.Signals (slice B) exists.
	var s Signals
	ctx := ScanContext{Collector: &s}
	if ctx.Collector == nil {
		t.Fatal("Collector field not wired")
	}
}

func TestResultV2Fields(t *testing.T) {
	r := Result{
		ScoringModel: "v2",
		SubScores:    []GroupScore{{Group: GroupExposure, Score: 80}},
		CapDriver:    &CapDriver{CheckID: "FW001", Grade: "RED"},
		NotAssessed:  []Finding{{CheckID: "HRD004", Status: StatusNotAssessed}},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Result
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ScoringModel != "v2" || len(got.SubScores) != 1 ||
		got.CapDriver == nil || got.CapDriver.CheckID != "FW001" ||
		len(got.NotAssessed) != 1 {
		t.Fatalf("v2 fields round-trip mismatch: %+v", got)
	}
}

func TestResultV2FieldsOmitEmpty(t *testing.T) {
	r := Result{Target: "x"}
	b, _ := json.Marshal(r)
	// None of the v2 keys appear when unset.
	for _, k := range []string{"scoring_model", "sub_scores", "cap_driver", "not_assessed"} {
		if containsKey(b, k) {
			t.Errorf("empty Result JSON unexpectedly contains %q: %s", k, b)
		}
	}
}

func containsKey(b []byte, key string) bool {
	return len(b) > 0 && bytesIndex(string(b), `"`+key+`"`) >= 0
}

func bytesIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
