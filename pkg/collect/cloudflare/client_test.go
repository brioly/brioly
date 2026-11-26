package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const clientToken = "cf-client-test-token-1111"

func TestClientRefusesAnAddressThatIsNotHTTPS(t *testing.T) {
	for _, base := range []string{"http://api.example.com/client/v4", "ftp://127.0.0.1", "api.example.com", "http://127.0.0.1.example.com"} {
		if _, err := NewClient(base, clientToken); err == nil {
			t.Errorf("NewClient(%q) accepted an address the token must not be sent to", base)
		}
	}
	if _, err := NewClient("", " "); err == nil {
		t.Error("NewClient accepted an empty token")
	}
	c, err := NewClient("", clientToken)
	if err != nil || c.base != DefaultBaseURL {
		t.Errorf("default address: %v %v", c, err)
	}
}

// A redirect is not followed: the token goes to the configured address only.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/zones", http.StatusFound)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, clientToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "/zones", "/zones"); err == nil {
		t.Error("a redirect was treated as an answer")
	}
	if elsewhere.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

// Whatever an answer or a failure says, an error never carries the token
// or the identifiers in the address.
func TestErrorsCarryNeitherTokenNorAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		// An API (or a proxy in between) that echoes the request.
		w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"bad header ` + r.Header.Get("Authorization") + `\nsecond line"}]}`))
	}))
	c, err := NewClient(srv.URL, clientToken)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background(), "/zones/{zone}/dns_records", "/zones/0000000000000000000000000000abcd/dns_records?page=1")
	if err == nil {
		t.Fatal("no error for a 403")
	}
	check := func(err error) {
		t.Helper()
		for _, never := range []string{clientToken, "0000000000000000000000000000abcd", "\n", srv.URL} {
			if strings.Contains(err.Error(), never) {
				t.Errorf("error carries %q: %v", never, err)
			}
		}
		if !strings.Contains(err.Error(), "/zones/{zone}/dns_records") {
			t.Errorf("error does not name the request: %v", err)
		}
	}
	check(err)
	// The connection fails: the HTTP client's own error names the address.
	srv.Close()
	_, err = c.Get(context.Background(), "/zones/{zone}/dns_records", "/zones/0000000000000000000000000000abcd/dns_records?page=1")
	if err == nil {
		t.Fatal("no error from a closed server")
	}
	check(err)
}

func TestClientWaitsWhenRateLimited(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"success":true,"result":[{"id":"a"}]}`))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, clientToken)
	if err != nil {
		t.Fatal(err)
	}
	var waited []time.Duration
	c.wait = func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }
	items, err := all[struct{ ID string }](context.Background(), c, "/x", "/x")
	if err != nil || len(items) != 1 {
		t.Fatalf("items %v, err %v", items, err)
	}
	if len(waited) != 2 || waited[0] != 7*time.Second {
		t.Errorf("waited %v, want twice for 7s", waited)
	}
	// It gives up after a few tries instead of waiting for ever.
	n.Store(-100)
	if _, err := c.Get(context.Background(), "/x", "/x"); err == nil {
		t.Error("no error although the API never stopped rate limiting")
	}
}

// A list whose API does not say where it ends is read once, and one that
// reports its size is read until that size.
func TestListStopsAtTheEnd(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/whole": // ignores page: always everything, no result_info
			w.Write([]byte(`{"success":true,"result":[{"id":"a"},{"id":"b"}]}`))
		case "/counted": // no total_pages, as the tunnels list
			page := r.URL.Query().Get("page")
			w.Write([]byte(`{"success":true,"result":[{"id":"` + page + `"}],"result_info":{"page":` + page + `,"per_page":1,"count":1,"total_count":3}}`))
		case "/null":
			w.Write([]byte(`{"success":true,"result":null}`))
		}
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, clientToken)
	for path, want := range map[string]int{"/whole": 2, "/counted": 3, "/null": 0} {
		items, err := list[struct{ ID string }](context.Background(), c, path, path, 0)
		if err != nil || len(items) != want {
			t.Errorf("%s: %d items, err %v; want %d", path, len(items), err, want)
		}
	}
	if calls.Load() != 1+3+1 {
		t.Errorf("%d requests, want 5", calls.Load())
	}
}

// A 4xx is the API's refusal only when the body is the API's own error
// envelope. A block page, a proxy's answer or an empty body says nothing
// about the token or the resource: it is ErrNotAPI, a failure that may pass.
// The first three bodies are what the real API answers a token it does not
// know (checked on 2026-11-26 with a made-up token).
func TestOnlyTheAPIsOwnAnswerIsARefusal(t *testing.T) {
	const html = `<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body>Sorry, you have been blocked</body></html>`
	cases := []struct {
		name   string
		status int
		ctype  string
		body   string
		want   error
	}{
		{"verify, unknown token", 401, "application/json", `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}],"messages":[],"result":null}`, ErrDenied},
		{"list, unknown token", 403, "application/json", `{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"messages":[],"result":null}`, ErrDenied},
		{"list, no permission", 403, "application/json", `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}],"messages":[],"result":null}`, ErrDenied},
		{"no such thing", 404, "application/json", `{"success":false,"errors":[{"code":7003,"message":"Could not route to /client/v4/x"}],"result":null}`, ErrNotFound},
		{"bad request", 400, "application/json", `{"success":false,"errors":[{"code":6003,"message":"Invalid request headers"}],"result":null}`, ErrRejected},
		{"block page", 403, "text/html", html, ErrNotAPI},
		{"block page, 401", 401, "text/html", html, ErrNotAPI},
		{"plain 400", 400, "text/plain", "Bad Request", ErrNotAPI},
		{"plain 404", 404, "text/plain", "404 page not found", ErrNotAPI},
		{"empty 403", 403, "", "", ErrNotAPI},
		{"JSON that is not the envelope", 403, "application/json", `{"error":"forbidden"}`, ErrNotAPI},
		{"an envelope without an error", 403, "application/json", `{"success":false,"errors":[]}`, ErrNotAPI},
		{"an envelope that says success", 403, "application/json", `{"success":true,"errors":[{"code":1000}],"result":[]}`, ErrNotAPI},
		{"an error without a code", 401, "application/json", `{"success":false,"errors":[{"message":"no"}]}`, ErrNotAPI},
	}
	var now atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := cases[now.Load()]
		if c.ctype != "" {
			w.Header().Set("Content-Type", c.ctype)
		}
		w.WriteHeader(c.status)
		w.Write([]byte(c.body))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, clientToken)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		now.Store(int32(i))
		_, err := c.Get(context.Background(), "/zones", "/zones")
		for _, kind := range []error{ErrDenied, ErrNotFound, ErrRejected, ErrNotAPI} {
			if got := errors.Is(err, kind); got != (kind == tc.want) {
				t.Errorf("%s (%d): errors.Is(%v) = %v; the error is %v", tc.name, tc.status, kind, got, err)
			}
		}
		// Only the API's own refusals stay the same until someone changes
		// something. The rest may pass, and earlier facts are kept.
		if stable(err) != (tc.want != ErrNotAPI) {
			t.Errorf("%s: stable = %v", tc.name, stable(err))
		}
		if strings.Contains(err.Error(), "blocked") || strings.Contains(err.Error(), "Invalid") {
			t.Errorf("%s: the error repeats the body: %v", tc.name, err)
		}
	}
}

// The status line's text is the other end's to write. It is not repeated:
// an upstream that echoes the Authorization header there gets none of it
// into an error.
func TestTheStatusLinesTextIsNotRepeated(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				auth := ""
				for _, line := range strings.Split(string(buf[:n]), "\r\n") {
					if strings.HasPrefix(line, "Authorization: Bearer ") {
						auth = strings.TrimPrefix(line, "Authorization: Bearer ")
					}
				}
				status := "403"
				if strings.Contains(string(buf[:n]), "GET /five") {
					status = "502"
				}
				body := `{"success":false,"errors":[{"code":9109,"message":"x"}]}`
				// Part of the token, as a proxy that logs its input might.
				fmt.Fprintf(conn, "HTTP/1.1 %s Denied for %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					status, auth[4:], len(body), body)
			}()
		}
	}()
	c, err := NewClient("http://"+ln.Addr().String(), clientToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/four", "/five"} {
		_, err := c.Get(context.Background(), path, path)
		if err == nil {
			t.Fatalf("%s: no error", path)
		}
		if strings.Contains(err.Error(), clientToken[4:]) || strings.Contains(err.Error(), clientToken[8:16]) || strings.Contains(err.Error(), "Denied for") {
			t.Errorf("%s: the error repeats the status line: %v", path, err)
		}
	}
	if _, err := c.Get(context.Background(), "/four", "/four"); !strings.Contains(err.Error(), "403 Forbidden (Cloudflare error code 9109)") {
		t.Errorf("the reason is not made from the status code: %v", err)
	}
}

// A caller that sends someone else's token does not let the environment
// name a proxy for it.
func TestNoProxy(t *testing.T) {
	c, err := NewClient("", clientToken, ClientOptions{NoProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Errorf("with NoProxy the transport is %T and may still use a proxy", c.http.Transport)
	}
	c, _ = NewClient("", clientToken)
	if c.http.Transport != nil {
		t.Error("without NoProxy the default transport, which honours the environment, is not used")
	}
}
