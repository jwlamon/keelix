package model

import (
	"encoding/json"
	"testing"
)

func TestFindingNewFieldsDefaults(t *testing.T) {
	var f Finding
	// Zero values: ConfidenceHigh, StatusAssessed, ExposureUnknown, not fatal.
	if f.Confidence != ConfidenceHigh {
		t.Errorf("zero Confidence = %d, want ConfidenceHigh", f.Confidence)
	}
	if f.Status != StatusAssessed {
		t.Errorf("zero Status = %d, want StatusAssessed", f.Status)
	}
	if f.ExposureClass != ExposureUnknown {
		t.Errorf("zero ExposureClass = %d, want ExposureUnknown", f.ExposureClass)
	}
	if f.Fatal {
		t.Error("zero Fatal = true, want false")
	}
	if f.BaseImpact != 0 {
		t.Errorf("zero BaseImpact = %v, want 0", f.BaseImpact)
	}
	if f.Mitigations != nil {
		t.Errorf("zero Mitigations = %v, want nil", f.Mitigations)
	}
}

func TestFindingNewFieldsRoundTrip(t *testing.T) {
	f := Finding{
		CheckID:       "EXP001",
		BaseImpact:    9.0,
		Confidence:    ConfidenceMedium,
		ExposureClass: ExposureInternet,
		Mitigations:   []string{"reverse-proxy auth"},
		Fatal:         true,
		Status:        StatusNotAssessed,
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Finding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.BaseImpact != 9.0 || got.Confidence != ConfidenceMedium ||
		got.ExposureClass != ExposureInternet || got.Fatal != true ||
		got.Status != StatusNotAssessed || len(got.Mitigations) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
