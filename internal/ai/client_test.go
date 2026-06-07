package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jwlamon/keelix/internal/model"
)

// stubTransport is a net/http RoundTripper that returns a canned response.
type stubTransport struct {
	statusCode int
	body       string
	// captured holds the last request so assertions can inspect it.
	captured *http.Request
	// capturedBody holds the raw request body bytes.
	capturedBody []byte
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Capture the request for assertions.
	s.captured = req
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		s.capturedBody = b
	}

	return &http.Response{
		StatusCode: s.statusCode,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
	}, nil
}

// cannedJSON returns a valid Anthropic messages response JSON with the given text.
func cannedJSON(text string) string {
	type block struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type resp struct {
		Content []block `json:"content"`
	}
	b, _ := json.Marshal(resp{Content: []block{{Type: "text", Text: text}}})
	return string(b)
}

// makeResult builds a minimal Result with one critical finding for testing.
func makeResult() *model.Result {
	return &model.Result{
		Target:    "test-stack",
		ScannedAt: time.Now(),
		Score:     40,
		Rating:    "RED",
		Counts: model.Counts{
			Critical: 1,
			Warning:  0,
			Passed:   3,
		},
		Findings: []model.Finding{
			{
				CheckID:  "EXP001",
				Title:    "PostgreSQL reachable from the internet (port 5432)",
				Severity: model.SeverityCritical,
				Passed:   false,
				Service:  "db",
				Resource: "port 5432",
				Detail:   "The database port is exposed to the internet.",
				Evidence: "TCP connect to :5432 succeeded from external vantage point.",
				Fix: model.Fix{
					Summary: "Remove port 5432 from compose ports mapping.",
					Diff:    "- ports:\n-   - \"5432:5432\"",
				},
			},
		},
	}
}

// TestNewClientDisabled verifies that a client with no API key is disabled
// and that Enrich is a no-op that leaves findings and AISummary untouched.
func TestNewClientDisabled(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("ANTHROPIC_MODEL", "")

	c := NewClient()
	if c.Enabled() {
		t.Fatal("expected Enabled() == false when ANTHROPIC_API_KEY is empty")
	}

	r := makeResult()
	originalExplanation := r.Findings[0].AIExplanation
	originalSummary := r.AISummary

	err := c.Enrich(context.Background(), r)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}

	if r.Findings[0].AIExplanation != originalExplanation {
		t.Errorf("AIExplanation was modified: got %q, want %q",
			r.Findings[0].AIExplanation, originalExplanation)
	}
	if r.AISummary != originalSummary {
		t.Errorf("AISummary was modified: got %q, want %q", r.AISummary, originalSummary)
	}
}

// TestEnrichSuccess verifies that a 200 response populates AIExplanation and AISummary,
// and that outgoing requests carry required headers and a JSON body with the model.
func TestEnrichSuccess(t *testing.T) {
	const responseText = "BECAUSE-X\n---\n- ports:\n-   - \"5432:5432\""
	stub := &stubTransport{
		statusCode: 200,
		body:       cannedJSON(responseText),
	}
	hc := &http.Client{Transport: stub}
	c := NewClientWithHTTP("test-key-abc", "claude-sonnet-4-6", "https://api.example.com", hc)

	if !c.Enabled() {
		t.Fatal("expected Enabled() == true")
	}

	r := makeResult()
	err := c.Enrich(context.Background(), r)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error: %v", err)
	}

	// The finding should have a non-empty AIExplanation.
	if r.Findings[0].AIExplanation == "" {
		t.Error("expected AIExplanation to be non-empty after successful enrichment")
	}

	// AISummary should be set (stub returns same text for every call).
	if r.AISummary == "" {
		t.Error("expected AISummary to be non-empty after successful enrichment")
	}

	// Verify outgoing request headers (captured is from the last call; check any call).
	// We call complete at least once, so captured should be non-nil.
	if stub.captured == nil {
		t.Fatal("no HTTP request was captured")
	}

	req := stub.captured
	if got := req.Header.Get("x-api-key"); got != "test-key-abc" {
		t.Errorf("x-api-key header: got %q, want %q", got, "test-key-abc")
	}
	if got := req.Header.Get("anthropic-version"); got != "2023-06-01" {
		t.Errorf("anthropic-version header: got %q, want %q", got, "2023-06-01")
	}
	if got := req.Header.Get("content-type"); got != "application/json" {
		t.Errorf("content-type header: got %q, want %q", got, "application/json")
	}

	// Verify the request body contains the model name.
	if len(stub.capturedBody) == 0 {
		t.Fatal("captured request body is empty")
	}
	var bodyMap map[string]interface{}
	if err := json.Unmarshal(stub.capturedBody, &bodyMap); err != nil {
		t.Fatalf("request body is not valid JSON: %v", err)
	}
	if got, ok := bodyMap["model"]; !ok || got != "claude-sonnet-4-6" {
		t.Errorf("request body model: got %v, want %q", got, "claude-sonnet-4-6")
	}
}

// TestEnrichGracefulOn500 verifies that a 500 response causes Enrich to silently
// degrade: it returns nil and leaves AIExplanation empty.
func TestEnrichGracefulOn500(t *testing.T) {
	stub := &stubTransport{
		statusCode: 500,
		body:       `{"error":"internal server error"}`,
	}
	hc := &http.Client{Transport: stub}
	c := NewClientWithHTTP("test-key-abc", "claude-sonnet-4-6", "https://api.example.com", hc)

	r := makeResult()
	err := c.Enrich(context.Background(), r)
	if err != nil {
		t.Fatalf("Enrich returned unexpected error on 500: %v — should degrade gracefully", err)
	}

	if r.Findings[0].AIExplanation != "" {
		t.Errorf("expected AIExplanation to remain empty on 500, got: %q",
			r.Findings[0].AIExplanation)
	}
	if r.AISummary != "" {
		t.Errorf("expected AISummary to remain empty on 500, got: %q", r.AISummary)
	}
}

// TestEnrichSkipsPassedFindings verifies that passing findings are not enriched.
func TestEnrichSkipsPassedFindings(t *testing.T) {
	stub := &stubTransport{
		statusCode: 200,
		body:       cannedJSON("ENRICHED"),
	}
	hc := &http.Client{Transport: stub}
	c := NewClientWithHTTP("test-key-abc", "claude-sonnet-4-6", "https://api.example.com", hc)

	r := &model.Result{
		Score:  100,
		Rating: "GREEN",
		Counts: model.Counts{Passed: 1},
		Findings: []model.Finding{
			{
				CheckID:  "OK001",
				Title:    "No exposed ports",
				Severity: model.SeverityOK,
				Passed:   true,
				Detail:   "All good.",
			},
		},
	}

	if err := c.Enrich(context.Background(), r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Passed findings must not be touched.
	if r.Findings[0].AIExplanation != "" {
		t.Errorf("expected AIExplanation to stay empty for passed finding, got: %q",
			r.Findings[0].AIExplanation)
	}
}

// TestDefaultModel verifies that ANTHROPIC_MODEL defaults to claude-sonnet-4-6.
func TestDefaultModel(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "some-key")
	t.Setenv("ANTHROPIC_MODEL", "")

	c := NewClient()
	if c.model != defaultModel {
		t.Errorf("default model: got %q, want %q", c.model, defaultModel)
	}
}

// TestCompleteParsesConcatenatedTextBlocks verifies that multiple text blocks
// in the content array are concatenated.
func TestCompleteParsesConcatenatedTextBlocks(t *testing.T) {
	multiBlock := `{"content":[{"type":"text","text":"Hello "},{"type":"text","text":"World"}]}`
	stub := &stubTransport{statusCode: 200, body: multiBlock}
	hc := &http.Client{Transport: stub}
	c := NewClientWithHTTP("key", "model", "https://api.example.com", hc)

	got, err := c.complete(context.Background(), "test prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "Hello World" {
		t.Errorf("expected concatenated text %q, got %q", "Hello World", got)
	}
}
