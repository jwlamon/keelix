package model_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestDomainOf(t *testing.T) {
	cases := []struct {
		group  model.CheckGroup
		domain model.ScoreDomain
	}{
		{model.GroupAIAgent, model.DomainAIMCP},
		{model.GroupMCP, model.DomainAIMCP},
		{model.GroupExposure, model.DomainBox},
		{model.GroupFirewall, model.DomainBox},
		{model.GroupProxy, model.DomainBox},
		{model.GroupHardening, model.DomainBox},
		{model.GroupSecrets, model.DomainBox},
		{model.GroupTLS, model.DomainBox},
		{model.GroupDNS, model.DomainBox},
		{model.GroupAuth, model.DomainBox},
		{model.GroupSupplyChain, model.DomainBox},
		{model.CheckGroup("unknown-future-group"), model.DomainBox},
	}
	for _, tc := range cases {
		got := model.DomainOf(tc.group)
		if got != tc.domain {
			t.Errorf("DomainOf(%q) = %q, want %q", tc.group, got, tc.domain)
		}
	}
}

func TestScoreDomainConsts(t *testing.T) {
	if model.DomainBox != "box" {
		t.Fatalf("DomainBox = %q, want %q", model.DomainBox, "box")
	}
	if model.DomainAIMCP != "ai-mcp" {
		t.Fatalf("DomainAIMCP = %q, want %q", model.DomainAIMCP, "ai-mcp")
	}
}
