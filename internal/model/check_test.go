package model_test

import (
	"testing"

	"github.com/jakelamon/keelix/internal/model"
)

func TestGroupServiceInGroupOrder(t *testing.T) {
	var supplyIdx, serviceIdx, agentIdx int
	found := map[model.CheckGroup]int{}
	for i, g := range model.GroupOrder {
		found[g] = i
	}
	var ok bool
	if supplyIdx, ok = found[model.GroupSupplyChain]; !ok {
		t.Fatal("GroupSupplyChain not in GroupOrder")
	}
	if serviceIdx, ok = found[model.GroupService]; !ok {
		t.Fatal("GroupService not in GroupOrder")
	}
	if agentIdx, ok = found[model.GroupAIAgent]; !ok {
		t.Fatal("GroupAIAgent not in GroupOrder")
	}
	if !(supplyIdx < serviceIdx && serviceIdx < agentIdx) {
		t.Errorf("GroupOrder: want GroupSupplyChain(%d) < GroupService(%d) < GroupAIAgent(%d)",
			supplyIdx, serviceIdx, agentIdx)
	}
}
