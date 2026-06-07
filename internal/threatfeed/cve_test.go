package threatfeed

import "testing"

func TestParseCVE(t *testing.T) {
	cases := []struct {
		in     string
		year   uint16
		seq    uint32
		wantOK bool
	}{
		{"CVE-2021-44228", 2021, 44228, true}, // Log4Shell
		{"CVE-2014-0160", 2014, 160, true},    // Heartbleed (leading zeros in seq)
		{"cve-2021-44228", 2021, 44228, true}, // lowercase prefix
		{"CVE-1999-0001", 1999, 1, true},
		{"CVE-2024-1234567", 2024, 1234567, true}, // long seq
		{"", 0, 0, false},
		{"CVE-2021", 0, 0, false},
		{"CVE-21-44228", 0, 0, false}, // 2-digit year
		{"NOTACVE", 0, 0, false},
		{"CVE-2021-", 0, 0, false},     // empty seq
		{"CVE-abcd-1234", 0, 0, false}, // non-numeric year
	}
	for _, c := range cases {
		y, s, ok := parseCVE(c.in)
		if ok != c.wantOK {
			t.Errorf("parseCVE(%q) ok = %v, want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && (y != c.year || s != c.seq) {
			t.Errorf("parseCVE(%q) = (%d,%d), want (%d,%d)", c.in, y, s, c.year, c.seq)
		}
	}
}
