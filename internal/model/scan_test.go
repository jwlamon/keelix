package model_test

import (
	"testing"

	"github.com/jwlamon/keelix/internal/model"
)

func TestScanOptionsMCPProbeFields(t *testing.T) {
	o := model.ScanOptions{
		MCPProbeEnabled:     true,
		MCPProbeConsent:     true,
		MCPProbeUnsandboxed: true,
	}
	if !o.MCPProbeEnabled || !o.MCPProbeConsent || !o.MCPProbeUnsandboxed {
		t.Fatal("MCP probe option fields not settable")
	}
}
