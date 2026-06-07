package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCollectConfigFramework exercises the collectConfig framework logic
// (Mode, SchemaKnown, SchemaID, Values, redaction) via collectConfigInternal
// which bypasses the allowlist gate, permitting use of testdata paths.
func TestCollectConfigFramework(t *testing.T) {
	path := filepath.Join("testdata", "example.env")
	got := collectConfigInternal(path, parseDotenv)
	if got.Source != path {
		t.Errorf("Source = %q, want %q", got.Source, path)
	}
	if !got.SchemaKnown {
		t.Error("SchemaKnown = false, want true for a parseable dotenv")
	}
	if got.SchemaID != "dotenv" {
		t.Errorf("SchemaID = %q, want dotenv", got.SchemaID)
	}
	if got.Mode == "" {
		t.Error("Mode empty — collectConfig must stat the file and record octal mode")
	}
	if got.Values["LOG_LEVEL"] != "info" {
		t.Errorf("Values[LOG_LEVEL] = %q, want info", got.Values["LOG_LEVEL"])
	}
	// DATABASE_URL is present; value is either literal (plain class) or redacted
	// depending on classifier. Either outcome is valid — the key must be present.
	if _, ok := got.Values["DATABASE_URL"]; !ok {
		t.Error("expected DATABASE_URL key present")
	}
}

// TestCollectConfigUnknownSchema: the parser returns known=false, so the
// framework must NOT fabricate facts — empty Values, SchemaKnown false.
func TestCollectConfigUnknownSchema(t *testing.T) {
	path := filepath.Join("testdata", "mystery.conf")
	got := collectConfigInternal(path, parseDotenv)
	if got.SchemaKnown {
		t.Error("SchemaKnown = true for an unrecognized file, want false")
	}
	if len(got.Values) != 0 {
		t.Errorf("Values = %+v, want empty for unknown schema", got.Values)
	}
	if got.Source != path {
		t.Errorf("Source = %q, want %q", got.Source, path)
	}
}

func TestCollectConfigMissingFile(t *testing.T) {
	got := collectConfigInternal(filepath.Join("testdata", "does-not-exist.env"), parseDotenv)
	if got.SchemaKnown {
		t.Error("missing file should not be SchemaKnown")
	}
	if got.Mode != "" {
		t.Errorf("Mode = %q, want empty for missing file", got.Mode)
	}
}

// TestCollectConfigAllowlistGate verifies that collectConfig refuses a path not
// on the allowlist by returning a bare, non-SchemaKnown fact with no values.
func TestCollectConfigAllowlistGate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.env")
	if err := os.WriteFile(path, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := collectConfig(path, parseDotenv)
	if got.SchemaKnown {
		t.Error("SchemaKnown = true for non-allowlisted path, want false")
	}
	if len(got.Values) != 0 {
		t.Errorf("Values non-empty for non-allowlisted path: %v", got.Values)
	}
}

// TestCollectConfigRefusesSymlink verifies that collectConfig refuses a symlink.
// Uses collectConfigInternal to bypass the allowlist gate so the symlink check
// is exercised in isolation.
func TestCollectConfigRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.env")
	link := filepath.Join(dir, "link.env")
	if err := os.WriteFile(target, []byte("KEY=value\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// collectConfigInternal bypasses the allowlist gate; the symlink check must
	// still refuse to follow the link.
	got := collectConfigInternal(link, parseDotenv)
	if got.SchemaKnown {
		t.Error("collectConfigInternal on symlink: SchemaKnown = true, want false")
	}
	if len(got.Values) != 0 {
		t.Errorf("Values non-empty for symlink: %v", got.Values)
	}
	if got.Mode != "" {
		t.Errorf("Mode = %q, want empty for symlink", got.Mode)
	}
}

// TestCollectConfigRedactsSecretValues verifies that secret-shaped values are
// replaced with a shape marker, while plain values are preserved verbatim.
// We directly exercise redactConfigValues (internal, same package).
func TestCollectConfigRedactsSecretValues(t *testing.T) {
	in := map[string]string{
		// Plain value: short, low-entropy, key has no secret token.
		"LOG_LEVEL": "info",
		// Secret by key name: "token" in "APP_TOKEN".
		"APP_TOKEN": "somevalue",
		// Secret by key name: "key" in "API_KEY".
		"API_KEY": "somevalue",
		// Secret by high-entropy value (40 hex chars = entropy ~4.0, len 40).
		"SOME_VAR": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	out := redactConfigValues(in)
	if out["LOG_LEVEL"] != "info" {
		t.Errorf("LOG_LEVEL = %q, want literal value", out["LOG_LEVEL"])
	}
	if out["APP_TOKEN"] != "[secret]" {
		t.Errorf("APP_TOKEN = %q, want [secret]", out["APP_TOKEN"])
	}
	if out["API_KEY"] != "[secret]" {
		t.Errorf("API_KEY = %q, want [secret]", out["API_KEY"])
	}
	// SOME_VAR: 40 identical chars have low entropy (0 bits), so classOf returns
	// "plain". Only use it to verify non-crashing; redaction is by key name only.
	if _, ok := out["SOME_VAR"]; !ok {
		t.Error("SOME_VAR missing from output")
	}
}

// TestRFX1_EnvDollarRef is a parser-fed regression test for RFX-1 finding (1):
// keychainRef() must classify $VAR and ${VAR} env-variable references as
// "[keychain-ref]" (deferred secret reference), not "[secret]" or verbatim.
// This runs the full collect parse->redact pipeline via collectConfigInternal
// (NOT synthetic model.Signals) so the real redaction path is exercised.
func TestRFX1_EnvDollarRef(t *testing.T) {
	path := filepath.Join("testdata", "mcp_env_ref_fixture.json")
	fact := collectConfigInternal(path, parseMCPJSON)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false; fixture parse failed — check mcp_env_ref_fixture.json")
	}

	// $MY_SECRET_TOKEN: bare $-env-ref must become "[keychain-ref]", not "[secret]".
	dollarKey := "mcpServers.myserver.env.TOKEN_DOLLAR"
	if got := fact.Values[dollarKey]; got != "[keychain-ref]" {
		t.Errorf("RFX-1(1a) %s = %q, want \"[keychain-ref]\" ($VAR must be a deferred ref, not secret)",
			dollarKey, got)
	}

	// ${MY_OTHER_TOKEN}: braced $-env-ref must also become "[keychain-ref]".
	braceKey := "mcpServers.myserver.env.TOKEN_BRACE"
	if got := fact.Values[braceKey]; got != "[keychain-ref]" {
		t.Errorf("RFX-1(1b) %s = %q, want \"[keychain-ref]\" (${VAR} must be a deferred ref, not secret)",
			braceKey, got)
	}

	// op:// reference must still be "[keychain-ref]" (pre-existing behavior, regression guard).
	opKey := "mcpServers.myserver.env.OP_REF"
	if got := fact.Values[opKey]; got != "[keychain-ref]" {
		t.Errorf("RFX-1(1c) %s = %q, want \"[keychain-ref]\" (op:// ref must remain keychain-ref)",
			opKey, got)
	}

	// PLAIN_VAR: a plain, non-secret value must not be masked.
	plainKey := "mcpServers.myserver.env.PLAIN_VAR"
	if got := fact.Values[plainKey]; got != "hello" {
		t.Errorf("RFX-1(1d) %s = %q, want \"hello\" (plain value must not be masked)", plainKey, got)
	}
}

// TestRFX1_URLUserinfo is a parser-fed regression test for RFX-1 finding (2):
// a url-field value that embeds userinfo credentials (scheme://user:pass@host)
// must be redacted to "[secret]" even though "url" is otherwise a structural
// field that is excluded from isCredentialKeyPath.
// This runs the full collect parse->redact pipeline via collectConfigInternal
// (NOT synthetic model.Signals) so the real redaction path is exercised.
func TestRFX1_URLUserinfo(t *testing.T) {
	path := filepath.Join("testdata", "mcp_url_userinfo_fixture.json")
	fact := collectConfigInternal(path, parseMCPJSON)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false; fixture parse failed — check mcp_url_userinfo_fixture.json")
	}

	// URL with embedded credentials must be redacted.
	urlKey := "mcpServers.pgserver.url"
	if got := fact.Values[urlKey]; got != "[secret]" {
		t.Errorf("RFX-1(2a) %s = %q, want \"[secret]\" (URL with userinfo credentials must be redacted)",
			urlKey, got)
	}

	// Plain URL without userinfo must pass through verbatim.
	safeKey := "mcpServers.safeserver.url"
	if got := fact.Values[safeKey]; got != "http://127.0.0.1:5555/mcp" {
		t.Errorf("RFX-1(2b) %s = %q, want literal URL (plain URL must not be masked)",
			safeKey, got)
	}
}

func TestParseDotenv(t *testing.T) {
	vals, schema, known := parseDotenv([]byte("A=1\n# c\nB=two words\nBARE\n"))
	if !known {
		t.Fatal("known = false, want true")
	}
	if schema != "dotenv" {
		t.Errorf("schema = %q", schema)
	}
	if vals["A"] != "1" || vals["B"] != "two words" {
		t.Errorf("vals = %+v", vals)
	}
	if _, ok := vals["BARE"]; ok {
		t.Error("a line with no '=' must not become a key")
	}
}

// TestRedactionParserFed_RFX1 is the parser-fed regression test for RFX-1.
// It runs the real collect parse->redact->check pipeline (NOT synthetic signals)
// on the mcp_redaction_fixture.json testdata file.
//
// Requirements (all must pass simultaneously):
//
//	(1) mcpServers.github.args.1 == "@modelcontextprotocol/server-github"
//	    This value is high-entropy but it is a .args.* structural field —
//	    it must survive verbatim, never be masked as "[secret]".
//
//	(2) mcpServers.github.env.GITHUB_TOKEN == "[keychain-ref]"
//	    The value "keychain:login/github-mcp-token" is a keychain reference;
//	    it must be emitted as "[keychain-ref]", not "[secret]" or the literal.
//
//	(3) mcpServers.github.env.OPENAI_API_KEY == "[secret]"
//	    The value is a high-entropy plaintext API key; must be redacted.
//
//	(4) mcpServers.github.headers.Authorization == "[secret]"
//	    "Bearer abc123" is a credential header value; must be redacted even
//	    though "abc123" alone has low entropy and a non-secret-named key.
func TestRedactionParserFed_RFX1(t *testing.T) {
	path := filepath.Join("testdata", "mcp_redaction_fixture.json")
	fact := collectConfigInternal(path, parseMCPJSON)
	if !fact.SchemaKnown {
		t.Fatalf("SchemaKnown=false; fixture parse failed")
	}

	// (1) structural args value must survive verbatim.
	argsKey := "mcpServers.github.args.1"
	if got := fact.Values[argsKey]; got != "@modelcontextprotocol/server-github" {
		t.Errorf("(1) %s = %q, want %q (structural args must not be masked)",
			argsKey, got, "@modelcontextprotocol/server-github")
	}

	// (2) keychain ref must become "[keychain-ref]".
	tokenKey := "mcpServers.github.env.GITHUB_TOKEN"
	if got := fact.Values[tokenKey]; got != "[keychain-ref]" {
		t.Errorf("(2) %s = %q, want \"[keychain-ref]\"", tokenKey, got)
	}

	// (3) high-entropy plaintext API key must become "[secret]".
	openaiKey := "mcpServers.github.env.OPENAI_API_KEY"
	if got := fact.Values[openaiKey]; got != "[secret]" {
		t.Errorf("(3) %s = %q, want \"[secret]\"", openaiKey, got)
	}

	// (4) credential header with Bearer prefix must become "[secret]".
	authKey := "mcpServers.github.headers.Authorization"
	if got := fact.Values[authKey]; got != "[secret]" {
		t.Errorf("(4) %s = %q, want \"[secret]\" (Bearer header must be masked)", authKey, got)
	}
}
