package cloudflare

import (
	"context"
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
