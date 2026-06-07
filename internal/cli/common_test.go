package cli

import "testing"

func TestInput_QuickstartDefaultsCollectOn(t *testing.T) {
	// No compose, no signals → quickstart: collection ON, probe OFF (no host).
	f := &scanFlags{}
	in, err := f.input()
	if err != nil {
		t.Fatalf("quickstart input() error: %v", err)
	}
	if !in.Collect || !in.Options.Collect {
		t.Errorf("quickstart must default Collect=true, got %v/%v", in.Collect, in.Options.Collect)
	}
	if !in.Options.NoProbe {
		t.Errorf("quickstart with no host must default NoProbe=true")
	}
	if in.ComposePath != "" {
		t.Errorf("ComposePath should be empty in quickstart, got %q", in.ComposePath)
	}
}

func TestInput_NoCollectWithNoTargetErrors(t *testing.T) {
	// --no-collect with no compose and no signals leaves nothing to assess.
	f := &scanFlags{noCollect: true}
	if _, err := f.input(); err == nil {
		t.Fatal("expected an error when --no-collect leaves nothing to assess")
	}
}

// TestInput_NoCollectSuppressesQuickstartAutoCollect verifies that --no-collect
// suppresses the quickstart auto-collect when signals are provided. With
// --signals but no compose, quickstart is still false (signals != ""), so
// noCollect only gates the (quickstart && !noCollect) branch.
// More directly: --no-collect without any target should error.
func TestInput_NoCollectWithSignalsSucceeds(t *testing.T) {
	// --signals provided, no compose: not a quickstart, noCollect has no
	// auto-collect to suppress (collect flag is false), so effectiveCollect=false.
	// Should succeed because signals file is the data source (engine handles it).
	f := &scanFlags{signals: "/dev/null", noCollect: true}
	in, err := f.input()
	if err != nil {
		t.Fatalf("--signals + --no-collect should not error: %v", err)
	}
	if in.Collect {
		t.Error("--no-collect with --signals must not enable collect")
	}
}

func TestInput_ComposeStillWorks(t *testing.T) {
	f := &scanFlags{compose: "../../testdata/clean/docker-compose.yml"}
	in, err := f.input()
	if err != nil {
		t.Fatalf("compose input() error: %v", err)
	}
	if in.ComposePath == "" {
		t.Fatal("compose path should be set")
	}
	if in.Collect { // -c without --collect must NOT auto-collect (backward compat)
		t.Errorf("compose scan without --collect must not collect")
	}
}

func TestInput_HostEnablesProbe(t *testing.T) {
	f := &scanFlags{compose: "../../testdata/clean/docker-compose.yml", host: "example.com"}
	in, err := f.input()
	if err != nil {
		t.Fatalf("input() error: %v", err)
	}
	if in.Options.NoProbe {
		t.Error("with a host and no --no-probe, NoProbe must stay false")
	}
}
