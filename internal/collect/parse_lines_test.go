package collect

import "testing"

func TestParseLinesPgHba(t *testing.T) {
	input := []byte("# comment\nhost all all 0.0.0.0/0 trust\nlocal all all peer\n")
	lines := parseNonEmptyLines(input)
	if len(lines) != 2 {
		t.Fatalf("got %d non-comment lines, want 2", len(lines))
	}
	if lines[0] != "host all all 0.0.0.0/0 trust" {
		t.Errorf("lines[0]=%q", lines[0])
	}
}

func TestParseLinesExports(t *testing.T) {
	input := []byte("/srv/nfs *(rw,no_root_squash)\n# nfs comment\n/data 192.168.1.0/24(rw)\n")
	lines := parseNonEmptyLines(input)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	if lines[0] != "/srv/nfs *(rw,no_root_squash)" {
		t.Errorf("lines[0]=%q", lines[0])
	}
}
