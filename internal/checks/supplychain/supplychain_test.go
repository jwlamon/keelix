package supplychain

import (
	"sort"
	"testing"

	"github.com/jwlamon/keelix/internal/intel"
	"github.com/jwlamon/keelix/internal/model"
	"github.com/jwlamon/keelix/internal/threatfeed"
)

// ---- Empty-stack NotAssessed (QF-1) ----

// TestSUPCompose_EmptyStackNotAssessed verifies SUP001-SUP004 return NotAssessed
// (not a vacuous Pass) on an empty stack to prevent grade inflation.
func TestSUPCompose_EmptyStackNotAssessed(t *testing.T) {
	runners := []struct {
		id  string
		run func(*model.ScanContext) []model.Finding
	}{
		{"SUP001", func(ctx *model.ScanContext) []model.Finding { return (&sup001{}).Run(ctx) }},
		{"SUP002", func(ctx *model.ScanContext) []model.Finding { return (&sup002{}).Run(ctx) }},
		{"SUP003", func(ctx *model.ScanContext) []model.Finding { return (&sup003{}).Run(ctx) }},
		{"SUP004", func(ctx *model.ScanContext) []model.Finding { return (&sup004{}).Run(ctx) }},
	}
	for _, r := range runners {
		for _, ctx := range []*model.ScanContext{
			{},
			{Stack: &model.Stack{}},
		} {
			fs := r.run(ctx)
			if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
				t.Errorf("%s: want 1 NotAssessed finding on empty stack, got %+v", r.id, fs)
			}
		}
	}
}

// ---- SUP001 ----

func TestSUP001_NoDigest(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "cache", Image: "redis:latest"},
		},
	}}
	findings := (&sup001{}).Run(ctx)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Errorf("expected info finding for unpinned image")
	}
	if f.Severity != model.SeverityInfo {
		t.Errorf("expected info severity, got %v", f.Severity)
	}
}

func TestSUP001_WithDigest(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "cache", Image: "redis@sha256:e96c03a6dda7d0f28a5ae2d09d32cfa041d8d52a3e3ec1d4c6b1e984b0eb0a8b"},
		},
	}}
	findings := (&sup001{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass for digest-pinned image, got %+v", findings)
	}
}

func TestSUP001_NoImages(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "app", Build: "./app"},
		},
	}}
	findings := (&sup001{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("expected pass when no images, got %+v", findings)
	}
}

// ---- SUP002 ----

func TestSUP002_EmptyFeedPass(t *testing.T) {
	SetCompromisedFeed(nil)
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "miner", Image: "evil/cryptominer:latest"},
		},
	}}
	findings := (&sup002{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("empty feed should always pass, got %+v", findings)
	}
}

func TestSUP002_CompromisedImageFlagged(t *testing.T) {
	SetCompromisedFeed([]string{"evil/cryptominer"})
	defer SetCompromisedFeed(nil) // reset after test

	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "miner", Image: "evil/cryptominer:latest"},
		},
	}}
	findings := (&sup002{}).Run(ctx)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Passed {
		t.Errorf("expected critical finding for compromised image")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("expected critical severity, got %v", f.Severity)
	}
}

func TestSUP002_UnrelatedImageNotFlagged(t *testing.T) {
	SetCompromisedFeed([]string{"evil/cryptominer"})
	defer SetCompromisedFeed(nil)

	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "cache", Image: "redis:latest"},
		},
	}}
	findings := (&sup002{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("clean image should pass, got %+v", findings)
	}
}

func TestSUP002_FeedReset(t *testing.T) {
	SetCompromisedFeed([]string{"evil/cryptominer"})
	SetCompromisedFeed(nil) // reset

	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{Name: "miner", Image: "evil/cryptominer:latest"},
		},
	}}
	findings := (&sup002{}).Run(ctx)
	if len(findings) != 1 || !findings[0].Passed {
		t.Errorf("after reset feed should pass, got %+v", findings)
	}
}

// ---- SUP003 (KEV image) ----

func TestSUP003_KEVImageFires(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "app",
				Image: "keelixtest/log4j-demo:1.0",
				Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 8080}},
			},
		},
	}}
	fs := (&sup003{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Passed {
		t.Fatal("expected a failing SUP003 finding for a KEV image")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Metadata["cve"] != "CVE-2021-44228" {
		t.Errorf("Metadata[cve] = %q, want CVE-2021-44228", f.Metadata["cve"])
	}
	if f.Metadata["port"] != "8080" {
		t.Errorf("Metadata[port] = %q, want 8080 (for exposure classification)", f.Metadata["port"])
	}
	if f.Confidence != model.ConfidenceHigh {
		t.Errorf("confidence = %v, want High", f.Confidence)
	}
}

func TestSUP003_CleanImagePasses(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{{Name: "cache", Image: "redis:7"}},
	}}
	fs := (&sup003{}).Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Errorf("clean image should pass, got %+v", fs)
	}
}

func TestSUP003_EPSSOnlyImageDoesNotFire(t *testing.T) {
	// keelixtest/epss-demo maps to a high-EPSS NON-KEV CVE — SUP003 must NOT fire
	// (that is SUP004's job).
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{{Name: "x", Image: "keelixtest/epss-demo:1.0"}},
	}}
	fs := (&sup003{}).Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Errorf("EPSS-only image should pass SUP003, got %+v", fs)
	}
}

func TestSUP003_NoStackNotAssessed(t *testing.T) {
	fs := (&sup003{}).Run(&model.ScanContext{})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Errorf("no stack should be NotAssessed, got %+v", fs)
	}
}

func TestSUP003_EmptyServicesNotAssessed(t *testing.T) {
	fs := (&sup003{}).Run(&model.ScanContext{Stack: &model.Stack{}})
	if len(fs) != 1 || fs[0].Status != model.StatusNotAssessed {
		t.Errorf("empty-services stack should be NotAssessed, got %+v", fs)
	}
}

// ---- SUP004 (high-EPSS image) ----

func TestSUP004_HighEPSSImageFires(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{{Name: "x", Image: "keelixtest/epss-demo:1.0"}},
	}}
	fs := (&sup004{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Passed {
		t.Fatal("expected a failing SUP004 finding for a high-EPSS image")
	}
	if f.Severity != model.SeverityWarning {
		t.Errorf("severity = %v, want Warning", f.Severity)
	}
	// CVE-2022-42889 (Text4Shell, Apache Commons Text) — real non-KEV EPSS pctl=200
	// in the committed blob; keelixtest/epss-demo is mapped to it.
	if f.Metadata["cve"] != "CVE-2022-42889" {
		t.Errorf("Metadata[cve] = %q, want CVE-2022-42889", f.Metadata["cve"])
	}
	if f.Fatal {
		t.Error("SUP004 must not be Fatal")
	}
}

func TestSUP004_KEVImageDoesNotFire(t *testing.T) {
	// A KEV image is SUP003's domain; SUP004 must pass it (no high-EPSS non-KEV CVE).
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{{Name: "app", Image: "keelixtest/log4j-demo:1.0"}},
	}}
	fs := (&sup004{}).Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Errorf("KEV image should pass SUP004, got %+v", fs)
	}
}

func TestSUP004_CleanImagePasses(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{{Name: "cache", Image: "redis:7"}},
	}}
	fs := (&sup004{}).Run(ctx)
	if len(fs) != 1 || !fs[0].Passed {
		t.Errorf("clean image should pass, got %+v", fs)
	}
}

// ---- SUP003 official-image (library/) end-to-end ----

// TestSUP003_OfficialImageViaLibraryForm verifies that a Docker Hub official
// image referenced in its canonical docker.io/library/<name> form fires SUP003
// when it maps to a KEV CVE in the curated intel table. This is the SF-2
// regression guard: if ImageBase stops stripping the "library/" prefix the
// lookup will silently miss and SUP003 will pass when it should fail.
//
// Solr is used as the fixture: imageCVEs["solr"] maps to CVE-2021-44228
// (Log4Shell, CISA KEV), so docker.io/library/solr:8.11 must fire SUP003.
func TestSUP003_OfficialImageViaLibraryForm(t *testing.T) {
	// docker.io/library/solr → ImageBase → "solr" → imageCVEs["solr"] →
	// [CVE-2021-44228] (KEV) → SUP003 fires.
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "search",
				Image: "docker.io/library/solr:8.11",
				Ports: []model.PortMapping{{HostPort: 8983, ContainerPort: 8983}},
			},
		},
	}}
	fs := (&sup003{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Passed {
		t.Fatal("expected a failing SUP003 finding for a KEV official image via library/ form")
	}
	if f.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want Critical", f.Severity)
	}
	if f.Metadata["cve"] != "CVE-2021-44228" {
		t.Errorf("Metadata[cve] = %q, want CVE-2021-44228", f.Metadata["cve"])
	}
}

// TestSUP003_LibraryPrefixOnlyImageFires verifies that a bare "library/<name>"
// reference (without the docker.io registry prefix) also fires SUP003. Docker
// clients may produce this form from a pull of an official image.
func TestSUP003_LibraryPrefixOnlyImageFires(t *testing.T) {
	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "search",
				Image: "library/solr:8.11",
				Ports: []model.PortMapping{{HostPort: 8983, ContainerPort: 8983}},
			},
		},
	}}
	fs := (&sup003{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Passed {
		t.Fatal("expected a failing SUP003 finding for a KEV image via library/ prefix")
	}
	if fs[0].Metadata["cve"] != "CVE-2021-44228" {
		t.Errorf("Metadata[cve] = %q, want CVE-2021-44228", fs[0].Metadata["cve"])
	}
}

// TestSUP003_WorstCVEByEPSSDesc verifies that when an image maps to multiple KEV
// CVEs with different EPSS percentiles, SUP003 surfaces the one with the highest
// EPSS bucket (not the lexicographically-lowest id). The fixture image
// "keelixtest/multi-kev-demo" maps to:
//
//	CVE-2021-44228 (bucket=200, pctl=1.0)  ← correct "worst" (highest EPSS)
//	CVE-2005-2773  (bucket=199, pctl=0.995) ← lexicographically earlier (wrong answer)
//
// The old sort.Strings(kev) → kev[0] path would surface CVE-2005-2773; this test
// guards the EPSS-descending ranking introduced in SF-7.
func TestSUP003_WorstCVEByEPSSDesc(t *testing.T) {
	const img = "keelixtest/multi-kev-demo:1.0"
	// Derive the expected representative from the REAL committed blob so this test
	// is regeneration-safe: the "worst" CVE is the mapped KEV-listed CVE with the
	// highest EPSS bucket (lexicographic-ascending tie-break), mirroring sup003.go's
	// ranking. Requiring >=2 KEV CVEs ensures the ranking is actually exercised and
	// the test can't silently degrade into a single-CVE no-op after a feed refresh.
	mapped, ok := intel.ImageCVEs(img)
	if !ok {
		t.Fatalf("fixture image %q has no CVE mapping", img)
	}
	var kev []string
	for _, cve := range mapped {
		if threatfeed.KEVListed(cve) {
			kev = append(kev, cve)
		}
	}
	if len(kev) < 2 {
		t.Fatalf("fixture %q must map to >=2 KEV-listed CVEs to exercise EPSS ranking; got %v", img, kev)
	}
	sort.Slice(kev, func(i, j int) bool {
		bi, _ := threatfeed.EPSSBucket(kev[i])
		bj, _ := threatfeed.EPSSBucket(kev[j])
		if bi != bj {
			return bi > bj
		}
		return kev[i] < kev[j]
	})
	wantCVE := kev[0]

	ctx := &model.ScanContext{Stack: &model.Stack{
		Services: []*model.Service{
			{
				Name:  "app",
				Image: img,
				Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 8080}},
			},
		},
	}}
	fs := (&sup003{}).Run(ctx)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.Passed {
		t.Fatal("expected a failing SUP003 finding")
	}
	if f.Metadata["cve"] != wantCVE {
		t.Errorf("worst CVE = %q, want %q (highest-EPSS-bucket KEV CVE among %v)", f.Metadata["cve"], wantCVE, kev)
	}
}
