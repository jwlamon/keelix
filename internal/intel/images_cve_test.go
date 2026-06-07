package intel

import (
	"strings"
	"testing"
)

func TestImageCVEs(t *testing.T) {
	// Tag + registry are stripped before lookup.
	cves, ok := ImageCVEs("docker.io/keelixtest/log4j-demo:1.0")
	if !ok {
		t.Fatal("expected a CVE mapping for log4j-demo")
	}
	if len(cves) != 1 || cves[0] != "CVE-2021-44228" {
		t.Errorf("log4j-demo CVEs = %v, want [CVE-2021-44228]", cves)
	}

	if _, ok := ImageCVEs("redis:7"); ok {
		t.Error("redis should have no CVE mapping (absence != clean)")
	}

	// Returned slice is a copy: mutating it must not corrupt the map.
	cves[0] = "MUTATED"
	again, _ := ImageCVEs("keelixtest/log4j-demo")
	if again[0] != "CVE-2021-44228" {
		t.Error("ImageCVEs returned a slice aliased to the package map")
	}
}

// TestAllImageCVEEntriesResolve is a table-driven regression guard that asserts
// every entry in the curated imageCVEs map is reachable from a plausible
// canonical reference. For official Docker Hub images (keys with no "/"), the
// canonical form is docker.io/library/<key>:<tag>; for named-user images the
// canonical form is docker.io/<key>:<tag>. This test prevents SF-2-class
// regressions where the library/ stripping is broken or a new entry is added
// under a key that ImageBase cannot reach.
func TestAllImageCVEEntriesResolve(t *testing.T) {
	for key, wantCVEs := range imageCVEs {
		var canonical string
		if !strings.Contains(key, "/") {
			// Official Docker Hub image: docker.io/library/<key>
			canonical = "docker.io/library/" + key + ":latest"
		} else {
			// Named-user or organisation image
			canonical = "docker.io/" + key + ":latest"
		}
		got, ok := ImageCVEs(canonical)
		if !ok {
			t.Errorf("key %q: ImageCVEs(%q) returned false; ImageBase resolves to %q",
				key, canonical, ImageBase(canonical))
			continue
		}
		if len(got) != len(wantCVEs) {
			t.Errorf("key %q: got %d CVEs via canonical form, want %d", key, len(got), len(wantCVEs))
		}
	}
}
