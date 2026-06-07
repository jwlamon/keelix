package collect

import (
	"os"
	"testing"
)

// TestParseINI_SemicolonInValue verifies that a value beginning with ";" is NOT
// treated as an inline comment (bug a). Fixture: redis_semicolon_pass.conf.
func TestParseINI_SemicolonInValue(t *testing.T) {
	b, err := os.ReadFile("testdata/redis_semicolon_pass.conf")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m := parseINI(b)
	got := m["requirepass"]
	if got != ";p@ssw0rd!" {
		t.Errorf("requirepass=%q, want ;p@ssw0rd! (value starting with ; must not be stripped)", got)
	}
}

// TestParseINI_SectionNameLowercased verifies that section names are
// lowercased so that [Security] produces "security.*" keys (bug b).
// Fixture: grafana_capital_section.ini.
func TestParseINI_SectionNameLowercased(t *testing.T) {
	b, err := os.ReadFile("testdata/grafana_capital_section.ini")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m := parseINI(b)
	if m["security.admin_user"] != "admin" {
		t.Errorf("security.admin_user=%q, want admin (section must be lowercased)", m["security.admin_user"])
	}
	if m["auth.anonymous.enabled"] != "true" {
		t.Errorf("auth.anonymous.enabled=%q, want true (composite section must be lowercased)", m["auth.anonymous.enabled"])
	}
}

func TestParseINI_SectionsAndKeys(t *testing.T) {
	input := []byte("[section]\nkey=value\nother = spaced\n# comment\n\n[s2]\nfoo=bar\n")
	m := parseINI(input)
	if m["section.key"] != "value" {
		t.Errorf("section.key=%q, want value", m["section.key"])
	}
	if m["section.other"] != "spaced" {
		t.Errorf("section.other=%q, want spaced", m["section.other"])
	}
	if m["s2.foo"] != "bar" {
		t.Errorf("s2.foo=%q, want bar", m["s2.foo"])
	}
}

func TestParseINI_TopLevelKeys(t *testing.T) {
	input := []byte("bind 127.0.0.1\nprotected-mode yes\n")
	m := parseINI(input)
	if m["bind"] != "127.0.0.1" {
		t.Errorf("bind=%q, want 127.0.0.1", m["bind"])
	}
	if m["protected-mode"] != "yes" {
		t.Errorf("protected-mode=%q, want yes", m["protected-mode"])
	}
}

// TestParseINI_SinglePassCommentScan verifies that a value containing both ";"
// and "#" inline-comment delimiters is stripped at the FIRST
// whitespace-preceded delimiter — i.e. only one pass is done left-to-right —
// so "a ; b # c" becomes "a", not double-truncated to "a" via two sequential
// passes through both separators.  The critical invariant: the result must be
// "a" (truncate at the first ws-preceded delimiter found), NOT "a ; b" (only
// the second delimiter found) and NOT "" (over-stripped).
func TestParseINI_SinglePassCommentScan(t *testing.T) {
	// Space-delimited (redis/mosquitto style): "bind a ; b # c"
	input := []byte("bind a ; b # c\n")
	m := parseINI(input)
	got := m["bind"]
	if got != "a" {
		t.Errorf("bind=%q, want %q (first ws-preceded ; should truncate, leaving a)", got, "a")
	}

	// Equals-style: "key = a ; b # c"
	input2 := []byte("key = a ; b # c\n")
	m2 := parseINI(input2)
	got2 := m2["key"]
	if got2 != "a" {
		t.Errorf("key=%q, want %q (first ws-preceded ; should truncate)", got2, "a")
	}

	// Reverse order: "# before ;" — first ws-preceded delimiter is "#"
	input3 := []byte("key = a # b ; c\n")
	m3 := parseINI(input3)
	got3 := m3["key"]
	if got3 != "a" {
		t.Errorf("key=%q, want %q (first ws-preceded # should truncate)", got3, "a")
	}
}
