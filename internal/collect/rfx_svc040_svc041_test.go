package collect

// Parser-fed tests for SVC040 (Samba) and SVC041 (NFS).
// All ConfigFact construction routes through collectConfigInternal so the full
// parse→redact pipeline runs. Synthetic model.ConfigFact{Values: vals} literals
// that bypass redaction are forbidden per the FIX-10 discipline.

import (
	"path/filepath"
	"testing"

	_ "github.com/jakelamon/keelix/internal/checks/service"
	"github.com/jakelamon/keelix/internal/model"
)

func TestSVC040_ParserFed_GuestOk(t *testing.T) {
	c := findRegisteredCheck(t, "SVC040")

	t.Run("guest-ok share fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "smb_guestok.conf"),
			parseSmbConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseSmbConf did not recognise guestok fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "smb-conf" {
			t.Fatalf("SchemaID=%q, want smb-conf", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC040" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC040: want failing finding for guest-ok-shares=true; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("no guest shares passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "smb_no_guest.conf"),
			parseSmbConf,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseSmbConf did not recognise no-guest fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC040" && f.IsFail() {
				t.Errorf("SVC040: must NOT fire for smb.conf with no guest shares; got %+v", f)
			}
		}
	})
}

func TestSVC040_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC040")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC040: want NotAssessed when Collector==nil, got %+v", findings)
	}
}

// TestSVC040_ParserFed_GlobalGuestOk verifies that a top-level (pre-section)
// "guest ok = yes" directive is detected by parseSmbConf and SVC040 fires.
// Bug (b): dot<0 caused a continue, silently skipping the top-level key.
func TestSVC040_ParserFed_GlobalGuestOk(t *testing.T) {
	c := findRegisteredCheck(t, "SVC040")

	fact := collectConfigInternal(
		filepath.Join("testdata", "smb_global_guestok.conf"),
		parseSmbConf,
	)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false — parseSmbConf did not recognise global-guestok fixture; values: %v", fact.Values)
	}
	if fact.SchemaID != "smb-conf" {
		t.Fatalf("SchemaID=%q, want smb-conf", fact.SchemaID)
	}
	// The top-level "guest ok = yes" must be attributed to the (global) section.
	if fact.Values["guest-ok-shares"] == "" {
		t.Errorf("parseSmbConf: guest-ok-shares is empty on smb_global_guestok.conf; want (global) listed")
	}

	ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
	findings := c.Run(ctx)
	for _, f := range findings {
		if f.CheckID == "SVC040" && f.IsFail() {
			return
		}
	}
	t.Fatalf("SVC040: want failing finding for top-level guest ok = yes; got %+v\nValues: %v", findings, fact.Values)
}

func TestSVC041_ParserFed_NoRootSquash(t *testing.T) {
	c := findRegisteredCheck(t, "SVC041")

	t.Run("no_root_squash fires", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "nfs_norootsquash.exports"),
			parseNFSExports,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseNFSExports did not recognise norootsquash fixture; values: %v", fact.Values)
		}
		if fact.SchemaID != "nfs-exports" {
			t.Fatalf("SchemaID=%q, want nfs-exports", fact.SchemaID)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC041" && f.IsFail() {
				return
			}
		}
		t.Fatalf("SVC041: want failing finding for no_root_squash=true; got %+v\nValues: %v", findings, fact.Values)
	})

	t.Run("root_squash subnet-restricted passes", func(t *testing.T) {
		fact := collectConfigInternal(
			filepath.Join("testdata", "nfs_root_squash.exports"),
			parseNFSExports,
		)
		if !fact.SchemaKnown {
			t.Fatalf("SchemaKnown=false — parseNFSExports did not recognise root-squash fixture; values: %v", fact.Values)
		}
		ctx := &model.ScanContext{Collector: &model.Signals{Configs: []model.ConfigFact{fact}}}
		findings := c.Run(ctx)
		for _, f := range findings {
			if f.CheckID == "SVC041" && f.IsFail() {
				t.Errorf("SVC041: must NOT fire for root_squash subnet-restricted exports; got %+v", f)
			}
		}
	})
}

func TestSVC041_NoCollector_NotAssessed(t *testing.T) {
	c := findRegisteredCheck(t, "SVC041")
	findings := c.Run(&model.ScanContext{})
	if len(findings) != 1 || findings[0].Status != model.StatusNotAssessed {
		t.Fatalf("SVC041: want NotAssessed when Collector==nil, got %+v", findings)
	}
}
