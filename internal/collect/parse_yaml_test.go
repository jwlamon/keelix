package collect

import (
	"os"
	"testing"
)

// TestParseYAML_KeyWithLeadingHashComment verifies that a line of the form
// "key: # comment" is treated as a mapping node (empty value) rather than
// storing the comment text as the value (bug c).
// Fixture: traefik_insecure_commented.yml.
func TestParseYAML_KeyWithLeadingHashComment(t *testing.T) {
	b, err := os.ReadFile("testdata/traefik_insecure_commented.yml")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	m := parseYAML(b)
	got := m["api.insecure"]
	if got != "true" {
		t.Errorf("api.insecure=%q, want true (inline comment after colon must not become the value)", got)
	}
}

func TestParseYAML_FlatAndNested(t *testing.T) {
	input := []byte("top: val\nnested:\n  child: yes\n  deep:\n    leaf: 42\n")
	m := parseYAML(input)
	if m["top"] != "val" {
		t.Errorf("top=%q, want val", m["top"])
	}
	if m["nested.child"] != "yes" {
		t.Errorf("nested.child=%q, want yes", m["nested.child"])
	}
	if m["nested.deep.leaf"] != "42" {
		t.Errorf("nested.deep.leaf=%q, want 42", m["nested.deep.leaf"])
	}
}

func TestParseYAML_BoolAndMissing(t *testing.T) {
	input := []byte("enabled: false\nother: true\n")
	m := parseYAML(input)
	if m["enabled"] != "false" {
		t.Errorf("enabled=%q, want false", m["enabled"])
	}
	if m["other"] != "true" {
		t.Errorf("other=%q, want true", m["other"])
	}
}
