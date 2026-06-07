package model_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestNewGroupConstsExist(t *testing.T) {
	if model.GroupAIAgent != "AI Agent Posture" {
		t.Fatalf("GroupAIAgent = %q, want %q", model.GroupAIAgent, "AI Agent Posture")
	}
	if model.GroupMCP != "MCP Posture" {
		t.Fatalf("GroupMCP = %q, want %q", model.GroupMCP, "MCP Posture")
	}
}

func TestNewGroupsInGroupOrder(t *testing.T) {
	found := map[model.CheckGroup]bool{}
	for _, g := range model.GroupOrder {
		found[g] = true
	}
	for _, want := range []model.CheckGroup{model.GroupAIAgent, model.GroupMCP} {
		if !found[want] {
			t.Errorf("GroupOrder does not contain %q", want)
		}
	}
}

func TestGroupOrderEndsWithAIAfterSupplyChain(t *testing.T) {
	// GroupAIAgent and GroupMCP must appear after GroupSupplyChain.
	scIdx := -1
	aiIdx := -1
	mcpIdx := -1
	for i, g := range model.GroupOrder {
		switch g {
		case model.GroupSupplyChain:
			scIdx = i
		case model.GroupAIAgent:
			aiIdx = i
		case model.GroupMCP:
			mcpIdx = i
		}
	}
	if scIdx < 0 {
		t.Fatal("GroupSupplyChain not found in GroupOrder")
	}
	if aiIdx <= scIdx {
		t.Errorf("GroupAIAgent (idx %d) must come after GroupSupplyChain (idx %d)", aiIdx, scIdx)
	}
	if mcpIdx <= scIdx {
		t.Errorf("GroupMCP (idx %d) must come after GroupSupplyChain (idx %d)", mcpIdx, scIdx)
	}
}

func TestGroupHostConstExists(t *testing.T) {
	if model.GroupHost != "Host OS" {
		t.Fatalf("GroupHost = %q, want %q", model.GroupHost, "Host OS")
	}
}

func TestGroupHostIsFirstInGroupOrder(t *testing.T) {
	if len(model.GroupOrder) == 0 {
		t.Fatal("GroupOrder is empty")
	}
	if model.GroupOrder[0] != model.GroupHost {
		t.Fatalf("GroupOrder[0] = %q, want GroupHost (%q)", model.GroupOrder[0], model.GroupHost)
	}
}
