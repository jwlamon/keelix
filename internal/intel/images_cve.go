package intel

// imageCVEs maps an image BASE (as produced by ImageBase) to a curated,
// best-effort list of CVE ids known to affect well-known versions of that image.
//
// This is NOT a full SBOM/layer scan. Absence of an entry — or absence of a
// matching CVE in the embedded threat feed — is explicitly NOT a clean bill of
// health. The list is intentionally small and curated over the self-hoster image
// set; it pairs with internal/threatfeed to weight findings by real-world
// exploitability (CISA KEV / FIRST.org EPSS).
//
// The fixture entries below (CVE-2021-44228 Log4Shell on the log4j-demo base and
// CVE-2022-42889 Text4Shell on the epss-demo base) exist so the SUP003/SUP004
// checks can be exercised end-to-end against the committed threat-feed blob. Real
// curated mappings are added over time as well-known vulnerable image versions surface.
var imageCVEs = map[string][]string{
	// --- end-to-end fixtures (resolve against the committed threatfeed blob) ---
	"keelixtest/log4j-demo": {"CVE-2021-44228"}, // KEV → SUP003
	// CVE-2022-42889 (Apache Commons Text / "Text4Shell") — non-KEV, EPSS pctl=200
	// (bucket 200 > threshold 181) → SUP004; real record present in committed blob.
	"keelixtest/epss-demo": {"CVE-2022-42889"}, // high-EPSS non-KEV → SUP004
	// Two KEV CVEs with different EPSS buckets — verifies worst-CVE is ranked by
	// EPSS desc, not lexicographic order:
	//   CVE-2021-44228: bucket 200 (pctl=1.0)  ← higher EPSS, correct "worst"
	//   CVE-2005-2773:  bucket 199 (pctl=0.995) ← lexicographically earlier
	// The test asserts worst == CVE-2021-44228 (EPSS-ranked), not CVE-2005-2773
	// (which the old sort.Strings would have selected).
	"keelixtest/multi-kev-demo": {"CVE-2021-44228", "CVE-2005-2773"}, // multi-KEV EPSS-rank fixture

	// --- curated real-world examples (best-effort) ---
	"vmware/vcenter":       {"CVE-2021-44228"}, // Log4Shell-era bundled log4j
	"solr":                 {"CVE-2021-44228"},
	"elasticsearch":        {"CVE-2021-44228"},
	"atlassian/confluence": {"CVE-2021-26855"},
}

// ImageCVEs returns the curated CVE ids associated with an image reference, via
// its normalized base. The boolean is false when the base is not in the map.
// Matching is exact on ImageBase output (lowercased, registry/tag/digest
// stripped) to avoid false positives from substring collisions.
func ImageCVEs(image string) ([]string, bool) {
	base := ImageBase(image)
	cves, ok := imageCVEs[base]
	if !ok || len(cves) == 0 {
		return nil, false
	}
	out := make([]string, len(cves))
	copy(out, cves)
	return out, true
}
