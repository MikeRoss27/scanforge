package inference

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ptrFloat64(v float64) *float64 {
	return &v
}

func TestOpenAICompatibleGenerate(t *testing.T) {
	var gotPath, gotAuth, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody = string(buf)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices": [{"message": {"content": "{\"insights\":[]}"}}],
			"usage": {"prompt_tokens": 10, "completion_tokens": 5}
		}`))
	}))
	defer server.Close()

	client := NewOpenAICompatible(server.URL, "secret-key", "qwen3.5-9b", 0)
	resp, err := client.Generate(context.Background(), Request{
		Messages:    []Message{{Role: "user", Content: "hi"}},
		Temperature: ptrFloat64(0.1),
		MaxTokens:   100,
		JSON:        true,
	})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	if gotPath != "/chat/completions" {
		t.Errorf("unexpected path %q", gotPath)
	}
	if gotAuth != "Bearer secret-key" {
		t.Errorf("unexpected auth header %q", gotAuth)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("request body not JSON: %v", err)
	}
	if payload["model"] != "qwen3.5-9b" {
		t.Errorf("model not sent: %v", payload["model"])
	}
	if payload["response_format"] == nil {
		t.Error("response_format json_object not requested")
	}
	if !strings.Contains(resp.Content, "insights") {
		t.Errorf("unexpected content %q", resp.Content)
	}
	if resp.PromptTokens != 10 || resp.CompletionTokens != 5 {
		t.Errorf("usage not parsed: %+v", resp)
	}
}

func TestOpenAICompatibleRequestModelOverride(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer server.Close()

	client := NewOpenAICompatible(server.URL, "", "", 0)
	if _, err := client.Generate(context.Background(), Request{Model: "override-model"}); err != nil {
		t.Fatalf("Generate error: %v", err)
	}
}

func TestOpenAICompatibleServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewOpenAICompatible(server.URL, "", "", 0)
	_, err := client.Generate(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention status: %v", err)
	}
}

func TestOpenAICompatibleNoChoices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer server.Close()

	client := NewOpenAICompatible(server.URL, "", "", 0)
	if _, err := client.Generate(context.Background(), Request{}); err == nil {
		t.Fatal("expected error when no choices are returned")
	}
}

func TestOpenAICompatibleContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer server.Close()

	client := NewOpenAICompatible(server.URL, "", "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Generate(ctx, Request{}); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
