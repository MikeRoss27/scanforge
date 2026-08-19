// Package inference abstracts the LLM transport behind a small interface so
// the triage engine never depends on a specific backend. The bundled client
// speaks the OpenAI-compatible chat completions API, which llama.cpp, vLLM,
// Ollama and most local/cloud servers expose.
package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message is one chat turn.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request is a chat completion request.
type Request struct {
	Model       string
	Messages    []Message
	Temperature float64
	MaxTokens   int
	// JSON asks the server for a JSON object response (response_format).
	JSON bool
}

// Response is the model's completion.
type Response struct {
	Content          string
	PromptTokens     int
	CompletionTokens int
}

// Client generates completions. Implementations must be safe for concurrent
// use and honor context cancellation.
type Client interface {
	Generate(ctx context.Context, req Request) (Response, error)
}

// OpenAICompatible is a Client for any server exposing /v1/chat/completions
// (llama.cpp, vLLM, Ollama, LM Studio, ...).
type OpenAICompatible struct {
	// BaseURL is the full API base, e.g. http://127.0.0.1:8080/v1.
	BaseURL string
	// APIKey is sent as a Bearer token; may be empty for local servers.
	APIKey string
	// Model is the default model name, overridable per request.
	Model string
	HTTP  *http.Client
}

// NewOpenAICompatible builds a client with a sane default timeout.
func NewOpenAICompatible(baseURL, apiKey, model string, timeout time.Duration) *OpenAICompatible {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &OpenAICompatible{
		BaseURL: strings.TrimRight(baseURL, "/"),
		APIKey:  apiKey,
		Model:   model,
		HTTP:    &http.Client{Timeout: timeout},
	}
}

// Generate posts a chat completion request and returns the first choice.
func (c *OpenAICompatible) Generate(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = c.Model
	}

	payload := map[string]any{
		"model":    model,
		"messages": req.Messages,
	}
	if req.Temperature != 0 {
		payload["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		payload["max_tokens"] = req.MaxTokens
	}
	if req.JSON {
		payload["response_format"] = map[string]string{"type": "json_object"}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Response{}, fmt.Errorf("inference: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("inference: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	httpResp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("inference: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 8<<20))
	if err != nil {
		return Response{}, fmt.Errorf("inference: read response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("inference: server returned %s: %s",
			httpResp.Status, truncate(string(respBody), 300))
	}

	var decoded struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return Response{}, fmt.Errorf("inference: parse response: %w", err)
	}
	if len(decoded.Choices) == 0 {
		return Response{}, fmt.Errorf("inference: no choices in response")
	}

	return Response{
		Content:          decoded.Choices[0].Message.Content,
		PromptTokens:     decoded.Usage.PromptTokens,
		CompletionTokens: decoded.Usage.CompletionTokens,
	}, nil
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "…"
}
