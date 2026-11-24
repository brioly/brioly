package enrich

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// Claude calls the Claude API with the user's own key (BYOK).
type Claude struct {
	client anthropic.Client
	model  string
}

// NewClaude returns a Claude model client.
func NewClaude(apiKey, model string) *Claude {
	return &Claude{client: anthropic.NewClient(option.WithAPIKey(apiKey)), model: model}
}

// Name implements Model.
func (c *Claude) Name() string { return c.model }

// JSON implements Model with structured outputs. It streams because document
// responses can be long, and enables server-side refusal fallbacks so a
// false-positive safety decline is re-served instead of failing the run.
func (c *Claude) JSON(ctx context.Context, req Request) ([]byte, error) {
	params := anthropic.BetaMessageNewParams{
		Model:     c.model,
		MaxTokens: 64000,
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		System: []anthropic.BetaTextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(userBlocks(req)...)},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffortHigh,
			Format: anthropic.BetaJSONOutputFormatParam{Schema: req.Schema},
		},
	}
	stream := c.client.Beta.Messages.NewStreaming(ctx, params)
	msg := anthropic.BetaMessage{}
	for stream.Next() {
		if err := msg.Accumulate(stream.Current()); err != nil {
			return nil, err
		}
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	switch msg.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return nil, fmt.Errorf("the model declined the request (%s): %s", msg.StopDetails.Category, msg.StopDetails.Explanation)
	case anthropic.BetaStopReasonMaxTokens:
		return nil, errors.New("the model response was cut off at the token limit")
	}
	text := finalText(msg.Content)
	if text == "" {
		return nil, errors.New("the model returned no text")
	}
	if !json.Valid([]byte(text)) {
		return nil, errors.New("the model returned invalid JSON")
	}
	return []byte(text), nil
}

// userBlocks puts the shared facts first, marked for caching, then the task.
func userBlocks(req Request) []anthropic.BetaContentBlockParamUnion {
	if req.Context == "" {
		return []anthropic.BetaContentBlockParamUnion{anthropic.NewBetaTextBlock(req.Prompt)}
	}
	return []anthropic.BetaContentBlockParamUnion{
		{OfText: &anthropic.BetaTextBlockParam{Text: req.Context, CacheControl: anthropic.NewBetaCacheControlEphemeralParam()}},
		anthropic.NewBetaTextBlock(req.Prompt),
	}
}

// finalText joins the text of the model that produced the final answer.
// With server-side fallbacks, a "fallback" block marks where a declining
// model's output ends and the next model's begins; text before the last
// such block belongs to a model that was replaced and must be discarded.
func finalText(content []anthropic.BetaContentBlockUnion) string {
	start := 0
	for i, b := range content {
		if b.Type == "fallback" {
			start = i + 1
		}
	}
	var text strings.Builder
	for _, b := range content[start:] {
		if b.Type == "text" {
			text.WriteString(b.Text)
		}
	}
	return text.String()
}

// Cached wraps a Model with a file cache keyed by the full request, so
// re-running generate on an unchanged environment costs nothing and returns
// the same documents.
type Cached struct {
	Inner Model
	Dir   string
}

// Name implements Model.
func (c Cached) Name() string { return c.Inner.Name() }

// JSON implements Model.
func (c Cached) JSON(ctx context.Context, req Request) ([]byte, error) {
	h := sha256.New()
	for _, part := range []string{PromptVersion, c.Inner.Name(), req.System, req.Context, req.Prompt, string(req.Schema)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	path := filepath.Join(c.Dir, hex.EncodeToString(h.Sum(nil))+".json")
	if b, err := os.ReadFile(path); err == nil && json.Valid(b) {
		return b, nil
	}
	b, err := c.Inner.JSON(ctx, req)
	if err != nil {
		return nil, err
	}
	if !json.Valid(b) {
		return nil, errors.New("model returned invalid JSON")
	}
	// Write to a temporary file and rename, so an interrupted run never
	// leaves a truncated entry behind.
	if err := os.MkdirAll(c.Dir, 0o700); err == nil {
		if tmp, err := os.CreateTemp(c.Dir, ".tmp-*"); err == nil {
			_, werr := tmp.Write(b)
			cerr := tmp.Close()
			if werr == nil && cerr == nil {
				_ = os.Rename(tmp.Name(), path)
			}
			_ = os.Remove(tmp.Name())
		}
	}
	return b, nil
}
