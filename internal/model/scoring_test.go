package model

import (
	"encoding/json"
	"testing"
)

func TestGroupScoreJSON(t *testing.T) {
	g := GroupScore{Group: GroupExposure, Score: 72, NotAssessed: 2}
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"group":"Network Exposure","score":72,"not_assessed":2}`
	if string(b) != want {
		t.Fatalf("GroupScore JSON = %s, want %s", b, want)
	}
}

func TestGroupScoreOmitsZeroNotAssessed(t *testing.T) {
	g := GroupScore{Group: GroupFirewall, Score: 100}
	b, _ := json.Marshal(g)
	if string(b) != `{"group":"Docker/Firewall Bypass","score":100}` {
		t.Fatalf("GroupScore JSON = %s", b)
	}
}

func TestCapDriverJSON(t *testing.T) {
	c := CapDriver{CheckID: "EXP001", Title: "Postgres on the internet", Reason: "fatal + internet", Grade: "RED"}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"check_id":"EXP001","title":"Postgres on the internet","reason":"fatal + internet","grade":"RED"}`
	if string(b) != want {
		t.Fatalf("CapDriver JSON = %s, want %s", b, want)
	}
}
