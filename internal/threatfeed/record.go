package threatfeed

import "encoding/binary"

// recordSize is the fixed on-disk width of one threatfeed record (bytes).
//
//	year uint16 (2) | seq uint32 (4) | flags uint8 (1) | pctl uint8 (1) = 8.
const recordSize = 8

// Flag bits packed into a record's flags byte.
const (
	flagKEV     uint8 = 1 << 0 // bit0: CVE is on the CISA KEV list.
	flagEPSS    uint8 = 1 << 1 // bit1: an EPSS percentile is present.
	pctlBuckets       = 200    // percentile = pctl / pctlBuckets, range [0,1].
)

// record is the decoded form of one 8-byte table entry.
type record struct {
	year  uint16
	seq   uint32
	flags uint8
	pctl  uint8
}

// kevListed reports whether this record's KEV flag is set.
func (r record) kevListed() bool { return r.flags&flagKEV != 0 }

// epssPresent reports whether this record carries an EPSS percentile.
func (r record) epssPresent() bool { return r.flags&flagEPSS != 0 }

// percentile decodes the quantized EPSS percentile into [0,1]. pctl values
// above pctlBuckets (possible only in a corrupted blob) are clamped to 1.0 so
// the weight formula 0.3 + 0.7*p can never produce a value exceeding 1.0.
func (r record) percentile() float64 {
	p := r.pctl
	if p > pctlBuckets {
		p = pctlBuckets
	}
	return float64(p) / float64(pctlBuckets)
}

// encodeRecord writes one record into an 8-byte little-endian buffer.
func encodeRecord(dst []byte, r record) {
	_ = dst[recordSize-1] // bounds-check hint
	binary.LittleEndian.PutUint16(dst[0:2], r.year)
	binary.LittleEndian.PutUint32(dst[2:6], r.seq)
	dst[6] = r.flags
	dst[7] = r.pctl
}

// decodeRecord reads one record from an 8-byte little-endian buffer.
func decodeRecord(src []byte) record {
	_ = src[recordSize-1] // bounds-check hint
	return record{
		year:  binary.LittleEndian.Uint16(src[0:2]),
		seq:   binary.LittleEndian.Uint32(src[2:6]),
		flags: src[6],
		pctl:  src[7],
	}
}

// quantizePercentile converts an EPSS percentile in [0,1] to a 0..200 bucket,
// clamped to that range and rounded to nearest. It is used by the generator and
// kept here so the encode/decode contract lives in one file.
func quantizePercentile(p float64) uint8 {
	if p <= 0 {
		return 0
	}
	if p >= 1 {
		return pctlBuckets
	}
	return uint8(p*float64(pctlBuckets) + 0.5)
}

// cmpKey orders two (year,seq) keys: -1, 0, +1.
func cmpKey(ay uint16, as uint32, by uint16, bs uint32) int {
	switch {
	case ay < by:
		return -1
	case ay > by:
		return 1
	case as < bs:
		return -1
	case as > bs:
		return 1
	default:
		return 0
	}
}
