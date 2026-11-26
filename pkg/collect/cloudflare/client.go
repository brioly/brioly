package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// DefaultBaseURL is the Cloudflare API (v4).
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// The three errors below are answers of the Cloudflare API itself: they
// are returned only when the body is the API's own error envelope
// ({"success": false, "errors": [{"code": ...}]}). A 4xx from anything
// else on the way (a block page, a proxy, an empty body) is ErrNotAPI: it
// says nothing about the token or the resource.

// ErrDenied is returned when the API refuses the token (401, 403): the
// token is wrong, or it lacks the permission the request needs.
var ErrDenied = errors.New("cloudflare: access denied")

// ErrNotFound is returned when the API says there is no such thing (404).
var ErrNotFound = errors.New("cloudflare: not found")

// ErrRejected is returned for any other answer that says the request
// itself is not acceptable (4xx): asking again will give the same answer.
var ErrRejected = errors.New("cloudflare: request not accepted")

// ErrNotAPI is returned for a 4xx whose body is not the API's error
// envelope: something between here and the API answered (an edge block, a
// proxy, a captive portal), or the API answered in a way it does not
// document. It is a failure that may pass, like an outage: nothing can be
// concluded from it about the token, a permission or what exists.
var ErrNotAPI = errors.New("cloudflare: the answer did not come from the Cloudflare API")

// API reads from the Cloudflare API. path is the path below the base
// address, with its query. what names the request in errors, with
// placeholders where path holds identifiers ("/zones/{zone}/dns_records"),
// so that an error says which permission is missing without carrying IDs.
type API interface {
	Get(ctx context.Context, what, path string) (Response, error)
}

// Response is the part of Cloudflare's answer a caller reads: the result,
// left undecoded, and where the page is in a list.
type Response struct {
	Result json.RawMessage
	Info   PageInfo
}

// PageInfo is result_info of a paginated list. Lists that are not
// paginated leave it empty.
type PageInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

// Client is an API over HTTPS with an API token. It only ever sends GET
// requests, and the token appears nowhere but in the Authorization header:
// not in an address, an error or a log.
type Client struct {
	base  string
	token string
	http  *http.Client
	// wait pauses before a retry; tests replace it.
	wait func(ctx context.Context, d time.Duration) error
}

// ClientOptions adjusts a Client.
type ClientOptions struct {
	// NoProxy sends requests straight to the API, whatever HTTPS_PROXY and
	// its relatives say. For a caller that sends someone else's token (a
	// service): a proxy named by the process's environment must not see it.
	// The CLI leaves it false: its user's proxy is the user's own.
	NoProxy bool
}

// NewClient returns a client for the API at base (DefaultBaseURL when
// empty). The address must be https, or a loopback address for tests: the
// token is sent to it.
func NewClient(base, token string, opts ...ClientOptions) (*Client, error) {
	var o ClientOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	var transport http.RoundTripper
	if o.NoProxy {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.Proxy = nil
		transport = t
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("cloudflare: no API token")
	}
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || !(u.Scheme == "https" || u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, errors.New("cloudflare: the API address must be an https address")
	}
	return &Client{
		base:  strings.TrimRight(base, "/"),
		token: strings.TrimSpace(token),
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			// A redirect is not followed: the token goes to the address
			// that was configured, or nowhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		wait: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
	}, nil
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// maxRetries bounds how often a rate-limited request is sent again.
const maxRetries = 3

// Get implements API.
func (c *Client) Get(ctx context.Context, what, path string) (Response, error) {
	for attempt := 0; ; attempt++ {
		resp, retryAfter, err := c.get(ctx, what, path)
		if err == nil || retryAfter == 0 || attempt == maxRetries {
			return resp, err
		}
		if werr := c.wait(ctx, retryAfter); werr != nil {
			return Response{}, werr
		}
	}
}

// get sends one request. A positive retryAfter says the API asked the
// caller to slow down and the request may be sent again.
func (c *Client) get(ctx context.Context, what, path string) (Response, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return Response{}, 0, fmt.Errorf("cloudflare: GET %s: the request could not be made", what)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// The error of the HTTP client names the full address, which holds
		// account and zone identifiers: keep only its cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return Response{}, 0, fmt.Errorf("cloudflare: GET %s: %s", what, c.clean(err.Error()))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return Response{}, 0, fmt.Errorf("cloudflare: GET %s: %s", what, c.clean(err.Error()))
	}
	var env struct {
		Success *bool `json:"success"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Result json.RawMessage `json:"result"`
		Info   PageInfo        `json:"result_info"`
	}
	parseErr := json.Unmarshal(body, &env)
	// The reason is made here from the status code. The status line's own
	// text is whatever the other end wrote, and is not repeated.
	reason := strconv.Itoa(resp.StatusCode)
	if text := http.StatusText(resp.StatusCode); text != "" {
		reason += " " + text
	}
	// The API's own refusal: its envelope, saying it failed, with a code.
	fromAPI := parseErr == nil && env.Success != nil && !*env.Success && len(env.Errors) > 0 && env.Errors[0].Code != 0
	// Cloudflare's error code is kept, its message is not: a message can
	// repeat the address of the request, identifiers included.
	if fromAPI {
		reason += fmt.Sprintf(" (Cloudflare error code %d)", env.Errors[0].Code)
	}
	client4xx := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := 5 * time.Second
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			wait = time.Duration(s) * time.Second
		}
		if wait > 30*time.Second {
			wait = 30 * time.Second
		}
		return Response{}, wait, fmt.Errorf("cloudflare: GET %s: %s", what, reason)
	case client4xx && !fromAPI:
		return Response{}, 0, fmt.Errorf("%w: GET %s: %s without the API's error body", ErrNotAPI, what, reason)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Response{}, 0, fmt.Errorf("%w: GET %s: %s", ErrDenied, what, reason)
	case resp.StatusCode == http.StatusNotFound:
		return Response{}, 0, fmt.Errorf("%w: GET %s: %s", ErrNotFound, what, reason)
	case client4xx:
		return Response{}, 0, fmt.Errorf("%w: GET %s: %s", ErrRejected, what, reason)
	case resp.StatusCode != http.StatusOK:
		return Response{}, 0, fmt.Errorf("cloudflare: GET %s: %s", what, reason)
	case parseErr != nil:
		return Response{}, 0, fmt.Errorf("cloudflare: GET %s: the answer is not JSON", what)
	case env.Success != nil && !*env.Success:
		return Response{}, 0, fmt.Errorf("cloudflare: GET %s: %s", what, reason)
	}
	return Response{Result: env.Result, Info: env.Info}, 0, nil
}

// clean makes text that came from outside safe for an error message: one
// line, bounded, and without the token should anything ever echo it.
func (c *Client) clean(s string) string {
	s = strings.ReplaceAll(s, c.token, "[token]")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}

// maxPages bounds a list, so that an API that never says it is finished
// cannot keep a scan running.
const maxPages = 2000

// list reads every page of a paginated list. perPage 0 leaves the page size
// to the API.
func list[T any](ctx context.Context, api API, what, path string, perPage int) ([]T, error) {
	var all []T
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for page := 1; ; page++ {
		q := "page=" + strconv.Itoa(page)
		if perPage > 0 {
			q += "&per_page=" + strconv.Itoa(perPage)
		}
		resp, err := api.Get(ctx, what, path+sep+q)
		if err != nil {
			return nil, err
		}
		var items []T
		if len(resp.Result) > 0 && string(resp.Result) != "null" {
			if err := json.Unmarshal(resp.Result, &items); err != nil {
				return nil, fmt.Errorf("cloudflare: GET %s: the answer has an unexpected shape", what)
			}
		}
		all = append(all, items...)
		info := resp.Info
		more := false
		switch {
		case len(items) == 0:
		case info.TotalPages > 0:
			more = page < info.TotalPages
		case info.TotalCount > 0:
			more = len(all) < info.TotalCount
		}
		if !more {
			return all, nil
		}
		if page == maxPages {
			return nil, fmt.Errorf("cloudflare: GET %s: the list does not end", what)
		}
	}
}

// all reads a list the API returns whole.
func all[T any](ctx context.Context, api API, what, path string) ([]T, error) {
	resp, err := api.Get(ctx, what, path)
	if err != nil {
		return nil, err
	}
	var items []T
	if len(resp.Result) > 0 && string(resp.Result) != "null" {
		if err := json.Unmarshal(resp.Result, &items); err != nil {
			return nil, fmt.Errorf("cloudflare: GET %s: the answer has an unexpected shape", what)
		}
	}
	return items, nil
}

// one reads a single object.
func one[T any](ctx context.Context, api API, what, path string) (T, error) {
	var v T
	resp, err := api.Get(ctx, what, path)
	if err != nil {
		return v, err
	}
	if err := json.Unmarshal(resp.Result, &v); err != nil {
		return v, fmt.Errorf("cloudflare: GET %s: the answer has an unexpected shape", what)
	}
	return v, nil
}
