package main

import (
	"flag"
	"log"
	"os"
)

// Release process (out-of-band, NOT run in CI):
//  1. Download the day's EPSS CSV:
//     curl -sSL https://epss.cyentia.com/epss_scores-current.csv.gz | gunzip > epss.csv
//  2. Download the CISA KEV catalog:
//     curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json > kev.json
//  3. Run the generator to refresh the embedded blob + snapshot:
//     go run ./internal/threatfeed/gen \
//     -epss epss.csv -kev kev.json -date "$(date -u +%F)" \
//     -out internal/threatfeed/data/threatfeed.bin.gz \
//     -snapshot-out internal/threatfeed/snapshot.go
//  4. Commit the regenerated blob + snapshot.go.
//
// This tool performs NO network I/O. CI uses the committed blob as-is.
func main() {
	var (
		epssPath     = flag.String("epss", "", "path to FIRST.org EPSS CSV (cve,epss,percentile)")
		kevPath      = flag.String("kev", "", "path to CISA KEV catalog JSON")
		outPath      = flag.String("out", "", "output path for threatfeed.bin.gz")
		snapshotPath = flag.String("snapshot-out", "", "output path for generated snapshot.go")
		date         = flag.String("date", "", "snapshot date YYYY-MM-DD")
	)
	flag.Parse()

	if *epssPath == "" || *kevPath == "" || *outPath == "" || *snapshotPath == "" || *date == "" {
		flag.Usage()
		log.Fatal("all of -epss, -kev, -out, -snapshot-out, -date are required")
	}

	// #nosec G304 -- paths come from release-engineer CLI flags, not untrusted input.
	epssF, err := os.Open(*epssPath)
	if err != nil {
		log.Fatalf("open epss: %v", err)
	}
	defer epssF.Close()
	// #nosec G304 -- paths come from release-engineer CLI flags, not untrusted input.
	kevF, err := os.Open(*kevPath)
	if err != nil {
		log.Fatalf("open kev: %v", err)
	}
	defer kevF.Close()

	recs, err := buildTable(epssF, kevF)
	if err != nil {
		log.Fatalf("build table: %v", err)
	}
	gz, err := gzipBytes(encodeTable(recs))
	if err != nil {
		log.Fatalf("gzip: %v", err)
	}
	// #nosec G306 -- a public data blob, not a secret; 0644 is intended.
	if err := os.WriteFile(*outPath, gz, 0o644); err != nil {
		log.Fatalf("write blob: %v", err)
	}
	// #nosec G306 -- generated Go source, not a secret; 0644 is intended.
	if err := os.WriteFile(*snapshotPath, []byte(snapshotSource(*date)), 0o644); err != nil {
		log.Fatalf("write snapshot: %v", err)
	}
	log.Printf("wrote %d records to %s and snapshot %s (date %s)", len(recs), *outPath, *snapshotPath, *date)
}
