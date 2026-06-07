package model

import "testing"

func TestConfidenceMultiplier(t *testing.T) {
	cases := []struct {
		c    Confidence
		want float64
	}{
		{ConfidenceHigh, 1.0},
		{ConfidenceMedium, 0.6},
		{ConfidenceLow, 0.3},
	}
	for _, tc := range cases {
		if got := tc.c.Multiplier(); got != tc.want {
			t.Errorf("Confidence(%d).Multiplier() = %v, want %v", tc.c, got, tc.want)
		}
	}
	// Zero value must be High (1.0).
	var zero Confidence
	if zero != ConfidenceHigh {
		t.Errorf("zero Confidence = %d, want ConfidenceHigh (0)", zero)
	}
}

func TestExposureClassMultiplier(t *testing.T) {
	cases := []struct {
		e    ExposureClass
		want float64
	}{
		{ExposureUnknown, 0.5},
		{ExposureLocalhost, 0.10},
		{ExposureOverlay, 0.15},
		{ExposureLAN, 0.35},
		{ExposureFiltered, 0.50},
		{ExposureInternet, 1.00},
	}
	for _, tc := range cases {
		if got := tc.e.Multiplier(); got != tc.want {
			t.Errorf("ExposureClass(%d).Multiplier() = %v, want %v", tc.e, got, tc.want)
		}
	}
}

func TestExposureClassCanCapRed(t *testing.T) {
	cases := []struct {
		e    ExposureClass
		want bool
	}{
		{ExposureUnknown, false},
		{ExposureLocalhost, false},
		{ExposureOverlay, false},
		{ExposureLAN, true},
		{ExposureFiltered, true},
		{ExposureInternet, true},
	}
	for _, tc := range cases {
		if got := tc.e.CanCapRed(); got != tc.want {
			t.Errorf("ExposureClass(%d).CanCapRed() = %v, want %v", tc.e, got, tc.want)
		}
	}
}

func TestFindingStatusZeroValue(t *testing.T) {
	var s FindingStatus
	if s != StatusAssessed {
		t.Errorf("zero FindingStatus = %d, want StatusAssessed (0)", s)
	}
}
