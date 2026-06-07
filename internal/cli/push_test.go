package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPushResultBearer(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"scan_id":"scan-abc"}`))
	}))
	defer srv.Close()

	body := []byte(`{"host_id":"host-1","score":100}`)
	status, respBody, err := pushResult(srv.URL, "kx_testtoken", body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 201 {
		t.Fatalf("expected 201, got %d", status)
	}
	if gotAuth != "Bearer kx_testtoken" {
		t.Fatalf("expected Bearer kx_testtoken, got %q", gotAuth)
	}
	if gotBody["host_id"] != "host-1" {
		t.Fatalf("expected host_id=host-1 in body, got %v", gotBody["host_id"])
	}
	if !strings.Contains(respBody, "scan-abc") {
		t.Fatalf("expected scan_id in response body, got %q", respBody)
	}
}

func TestPushResult402(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(402)
		_, _ = w.Write([]byte("plan limit"))
	}))
	defer srv.Close()

	status, body, err := pushResult(srv.URL, "kx_tok", []byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 402 {
		t.Fatalf("expected 402, got %d", status)
	}
	if body != "plan limit" {
		t.Fatalf("expected 'plan limit' body, got %q", body)
	}
}

func TestPushResult429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte("quota exceeded"))
	}))
	defer srv.Close()

	status, body, err := pushResult(srv.URL, "kx_tok", []byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 429 {
		t.Fatalf("expected 429, got %d", status)
	}
	_ = body
}

func TestPushResult401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()

	status, _, err := pushResult(srv.URL, "bad_token", []byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 401 {
		t.Fatalf("expected 401, got %d", status)
	}
}
