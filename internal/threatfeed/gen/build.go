// Command gen builds the embedded threatfeed blob + snapshot.go from a FIRST.org
// EPSS CSV and a CISA KEV catalog JSON. It is RELEASE-TIME ONLY and performs NO
// network I/O — downloading the daily EPSS CSV and KEV JSON is an out-of-band
// release step (see the comment in main.go). CI never runs this; CI uses the
// committed internal/threatfeed/data/threatfeed.bin.gz.
//
// IMPORTANT: there is intentionally NO //go:generate directive here. Running
// `go generate ./...` must never silently overwrite the production blob with the
// small fixture files in testdata/. The real release command is:
//
//	# 1. Download fresh feeds:
//	#    curl -sSL https://epss.cyentia.com/epss_scores-current.csv.gz | gunzip > epss.csv
//	#    curl -sSL https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json > kev.json
//	# 2. Regenerate the embedded blob:
//	#    go run ./internal/threatfeed/gen \
//	#      -epss epss.csv -kev kev.json -date "$(date -u +%F)" \
//	#      -out internal/threatfeed/data/threatfeed.bin.gz \
//	#      -snapshot-out internal/threatfeed/snapshot.go
//	# 3. Commit the regenerated blob + snapshot.go.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// genRecord mirrors internal/threatfeed.record but is duplicated here because
// main is a separate package and the on-disk format is the shared contract
// (8-byte LE: year u16, seq u32, flags u8, pctl u8). Keep in sync with
// internal/threatfeed/record.go.
type genRecord struct {
	year  uint16
	seq   uint32
	flags uint8
	pctl  uint8
}

const (
	genFlagKEV  uint8 = 1 << 0
	genFlagEPSS uint8 = 1 << 1
	genBuckets        = 200
)

// parseCVEKey splits "CVE-YYYY-NNNNN" into (year, seq). ok=false on malformed.
func parseCVEKey(cve string) (uint16, uint32, bool) {
	cve = strings.TrimSpace(cve)
	if len(cve) < 10 {
		return 0, 0, false
	}
	if !strings.EqualFold(cve[:4], "CVE-") {
		return 0, 0, false
	}
	rest := cve[4:]
	dash := strings.IndexByte(rest, '-')
	if dash != 4 {
		return 0, 0, false
	}
	y, err := strconv.ParseUint(rest[:dash], 10, 16)
	if err != nil {
		return 0, 0, false
	}
	sStr := rest[dash+1:]
	if sStr == "" {
		return 0, 0, false
	}
	s, err := strconv.ParseUint(sStr, 10, 32)
	if err != nil {
		return 0, 0, false
	}
	return uint16(y), uint32(s), true
}

func quantize(p float64) uint8 {
	switch {
	case p <= 0:
		return 0
	case p >= 1:
		return genBuckets
	default:
		return uint8(p*float64(genBuckets) + 0.5)
	}
}

// key is the map key for the union table.
type key struct {
	year uint16
	seq  uint32
}

// buildTable reads an EPSS CSV and a KEV JSON and returns the union table sorted
// ascending by (year, seq). EPSS rows set flagEPSS + the quantized percentile;
// KEV ids set flagKEV (merged into an existing EPSS row, or a new KEV-only row).
// Malformed CVE ids in either source are skipped (best-effort).
func buildTable(epss io.Reader, kev io.Reader) ([]genRecord, error) {
	table := map[key]genRecord{}

	// --- EPSS CSV ---
	sc := bufio.NewScanner(epss)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	sawHeader := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		// Skip the header row "cve,epss,percentile".
		if !sawHeader && strings.EqualFold(strings.TrimSpace(fields[0]), "cve") {
			sawHeader = true
			continue
		}
		sawHeader = true
		y, s, ok := parseCVEKey(fields[0])
		if !ok {
			continue
		}
		pctl, err := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		if err != nil {
			continue
		}
		k := key{y, s}
		r := table[k]
		r.year, r.seq = y, s
		r.flags |= genFlagEPSS
		r.pctl = quantize(pctl)
		table[k] = r
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read epss csv: %w", err)
	}

	// --- KEV JSON ---
	var kevDoc struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(kev).Decode(&kevDoc); err != nil {
		return nil, fmt.Errorf("decode kev json: %w", err)
	}
	for _, v := range kevDoc.Vulnerabilities {
		y, s, ok := parseCVEKey(v.CVEID)
		if !ok {
			continue
		}
		k := key{y, s}
		r := table[k]
		r.year, r.seq = y, s
		r.flags |= genFlagKEV
		table[k] = r
	}

	out := make([]genRecord, 0, len(table))
	for _, r := range table {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].year != out[j].year {
			return out[i].year < out[j].year
		}
		return out[i].seq < out[j].seq
	})
	return out, nil
}

// encodeTable serializes the sorted table to the fixed-width 8-byte LE format.
func encodeTable(recs []genRecord) []byte {
	buf := make([]byte, 0, len(recs)*8)
	for _, r := range recs {
		var b [8]byte
		binary.LittleEndian.PutUint16(b[0:2], r.year)
		binary.LittleEndian.PutUint32(b[2:6], r.seq)
		b[6] = r.flags
		b[7] = r.pctl
		buf = append(buf, b[:]...)
	}
	return buf
}

// gzipBytes gzips raw with default compression.
func gzipBytes(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	if _, err := gw.Write(raw); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// snapshotSource returns the Go source for the generated snapshot.go.
func snapshotSource(date string) string {
	return "// Code generated by internal/threatfeed/gen; DO NOT EDIT.\n" +
		"package threatfeed\n\n" +
		"// snapshotDateRaw is the YYYY-MM-DD date the embedded blob was generated.\n" +
		"const snapshotDateRaw = " + strconv.Quote(date) + "\n"
}
