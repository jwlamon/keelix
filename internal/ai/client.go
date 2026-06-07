// Package ai provides a best-effort Claude API client that enriches scan
// findings with plain-English explanations, remediation diffs, and an
// executive summary. It degrades gracefully to a no-op when no API key is set
// or when any individual API call fails — it never affects correctness.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jwlamon/keelix/internal/model"
)

const (
	defaultModel   = "claude-sonnet-4-6"
	defaultBaseURL = "https://api.anthropic.com"
	defaultTimeout = 60 * time.Second
)

// Client is a Claude API client. The zero value is disabled (no API key).
type Client struct {
	apiKey  string
	model   string
	baseURL string
	hc      *http.Client
}

// NewClient creates a Client using environment variables.
// ANTHROPIC_API_KEY sets the key; ANTHROPIC_MODEL overrides the model.
// When ANTHROPIC_API_KEY is empty the client is disabled.
func NewClient() *Client {
	key := os.Getenv("ANTHROPIC_API_KEY")
	m := os.Getenv("ANTHROPIC_MODEL")
	if m == "" {
		m = defaultModel
	}
	return NewClientWithHTTP(key, m, defaultBaseURL, &http.Client{Timeout: defaultTimeout})
}

// NewClientWithHTTP creates a Client with explicit configuration.
// Passing an empty apiKey produces a disabled client.
// This constructor is exported so tests can inject a stub *http.Client.
func NewClientWithHTTP(apiKey, model, baseURL string, hc *http.Client) *Client {
	if model == "" {
		model = defaultModel
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{
		apiKey:  apiKey,
		model:   model,
		baseURL: strings.TrimRight(baseURL, "/"),
		hc:      hc,
	}
}

// Enabled reports whether the client has an API key configured.
func (c *Client) Enabled() bool {
	return c.apiKey != ""
}

// Enrich enriches findings and generates an executive summary in r.
// It is best-effort: if the client is disabled or any call fails, it
// silently skips that enrichment and continues. It never returns an error
// that should cause the scan to fail — callers may safely ignore the return value.
func (c *Client) Enrich(ctx context.Context, r *model.Result) error {
	if !c.Enabled() {
		return nil
	}

	// Enrich each failing finding in place.
	for i := range r.Findings {
		f := &r.Findings[i]
		if !f.IsFail() {
			continue
		}

		// Build a concise prompt for explanation + diff.
		prompt := buildFindingPrompt(f)
		resp, err := c.complete(ctx, prompt)
		if err != nil {
			// Silently degrade — skip this finding.
			continue
		}

		// Split the response into explanation and diff sections.
		explanation, diff := parseExplanationDiff(resp)
		f.AIExplanation = explanation
		if diff != "" {
			f.AIDiff = diff
		}
	}

	// Generate executive summary.
	summaryPrompt := buildSummaryPrompt(r)
	summary, err := c.complete(ctx, summaryPrompt)
	if err == nil && summary != "" {
		r.AISummary = summary
	}

	return nil
}

// complete sends a single user message to the Claude Messages API and returns
// the concatenated text content. It returns an error on transport failure,
// non-2xx status, or JSON parsing failure.
func (c *Client) complete(ctx context.Context, prompt string) (string, error) {
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type requestBody struct {
		Model     string    `json:"model"`
		MaxTokens int       `json:"max_tokens"`
		Messages  []message `json:"messages"`
	}

	body := requestBody{
		Model:     c.model,
		MaxTokens: 1024,
		Messages: []message{
			{Role: "user", Content: prompt},
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("ai: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("ai: build request: %w", err)
	}
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	res, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("ai: http: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("ai: api status %d", res.StatusCode)
	}

	respBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("ai: read response: %w", err)
	}

	type contentBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type responseBody struct {
		Content []contentBlock `json:"content"`
	}

	var parsed responseBody
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", fmt.Errorf("ai: parse response: %w", err)
	}

	var sb strings.Builder
	for _, block := range parsed.Content {
		if block.Type == "text" {
			sb.WriteString(block.Text)
		}
	}
	return sb.String(), nil
}

// buildFindingPrompt creates a concise prompt asking for explanation + diff.
func buildFindingPrompt(f *model.Finding) string {
	var sb strings.Builder
	sb.WriteString("You are a DevSecOps expert. Provide a plain-English explanation of this security finding and a concrete remediation diff.\n\n")
	sb.WriteString("Finding:\n")
	fmt.Fprintf(&sb, "  Title: %s\n", f.Title)
	fmt.Fprintf(&sb, "  Severity: %s\n", f.Severity.String())
	if f.Service != "" {
		fmt.Fprintf(&sb, "  Service: %s\n", f.Service)
	}
	if f.Resource != "" {
		fmt.Fprintf(&sb, "  Resource: %s\n", f.Resource)
	}
	if f.Detail != "" {
		fmt.Fprintf(&sb, "  Detail: %s\n", f.Detail)
	}
	if f.Evidence != "" {
		fmt.Fprintf(&sb, "  Evidence: %s\n", f.Evidence)
	}
	if f.Fix.Summary != "" {
		fmt.Fprintf(&sb, "  Existing fix: %s\n", f.Fix.Summary)
	}
	if f.Fix.Diff != "" {
		fmt.Fprintf(&sb, "  Existing diff:\n%s\n", f.Fix.Diff)
	}
	sb.WriteString("\nRespond with exactly two sections separated by a line containing only \"---\":\n")
	sb.WriteString("1. A 2-3 sentence plain-English explanation of why this matters and the risk.\n")
	sb.WriteString("2. A concrete docker-compose.yml diff (unified diff format) to remediate the issue.\n")
	sb.WriteString("Be concise and specific. Do not add preamble or postamble outside these two sections.")
	return sb.String()
}

// parseExplanationDiff splits the AI response into explanation and diff parts.
// The convention is a line containing exactly "---" as a separator.
func parseExplanationDiff(resp string) (explanation, diff string) {
	parts := strings.SplitN(resp, "\n---\n", 2)
	explanation = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		diff = strings.TrimSpace(parts[1])
	}
	return
}

// buildSummaryPrompt creates a prompt for the executive summary.
func buildSummaryPrompt(r *model.Result) string {
	var sb strings.Builder
	sb.WriteString("You are a security advisor. Write a 3-5 sentence executive summary of this Docker Compose stack security scan.\n\n")
	fmt.Fprintf(&sb, "Score: %d/100 (%s)\n", r.Score, r.Rating)
	fmt.Fprintf(&sb, "Critical issues: %d\n", r.Counts.Critical)
	fmt.Fprintf(&sb, "Warnings: %d\n", r.Counts.Warning)
	fmt.Fprintf(&sb, "Passed checks: %d\n", r.Counts.Passed)

	// Collect critical/warning titles for context.
	var titles []string
	for _, f := range r.Findings {
		if f.IsFail() {
			titles = append(titles, fmt.Sprintf("[%s] %s", f.Severity.Label(), f.Title))
		}
	}
	if len(titles) > 0 {
		sb.WriteString("\nIssues found:\n")
		for _, t := range titles {
			fmt.Fprintf(&sb, "  - %s\n", t)
		}
	}

	sb.WriteString("\nWrite an executive summary suitable for a non-technical stakeholder. Be direct about risk level and top priorities. Do not use bullet points — write in prose.")
	return sb.String()
}
