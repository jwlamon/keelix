package cli

import "testing"

func TestScanCmdHasMCPProbeFlags(t *testing.T) {
	cmd := newScanCmd()
	for _, name := range []string{"probe-mcp", "probe-mcp-yes", "probe-mcp-unsandboxed"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("scan command missing --%s flag", name)
		}
	}
}

func TestScanFlagsCarryMCPProbeOptions(t *testing.T) {
	tmp := t.TempDir()
	compose := tmp + "/docker-compose.yml"
	if err := writeFile(compose, "services: {}\n"); err != nil {
		t.Fatal(err)
	}
	sf := scanFlags{compose: compose, probeMCP: true, probeMCPYes: true, probeMCPUnsandboxed: true}
	in, err := sf.input()
	if err != nil {
		t.Fatal(err)
	}
	if !in.Options.MCPProbeEnabled || !in.Options.MCPProbeConsent || !in.Options.MCPProbeUnsandboxed {
		t.Fatalf("flags did not propagate into Options: %+v", in.Options)
	}
}

func writeFile(path, body string) error {
	return osWriteFile(path, body)
}

func osWriteFile(path, body string) error {
	return writeTestFile(path, body)
}
