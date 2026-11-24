package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrDenied is returned when the API server refuses the caller (401, 403).
var ErrDenied = errors.New("kubernetes: access denied")

// API reads one page of a list from a cluster's API server. path is an
// absolute API path with its query, e.g. /apis/apps/v1/deployments?limit=500.
type API interface {
	Get(ctx context.Context, path string) ([]byte, error)
}

// Client is an API over HTTPS with a bearer token. It only ever sends GET
// requests.
type Client struct {
	server string
	token  string
	http   *http.Client
}

// NewClient returns a client for the API server at server, trusting the
// given CA certificates (PEM). An empty caPEM uses the system roots.
func NewClient(server string, caPEM []byte, token string) (*Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("kubernetes: the cluster's CA certificate could not be parsed")
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		server: strings.TrimRight(server, "/"),
		token:  token,
		http:   &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}},
	}, nil
}

// Get implements API.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w: GET %s: %s", ErrDenied, strings.SplitN(path, "?", 2)[0], resp.Status)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("kubernetes: GET %s: %s", strings.SplitN(path, "?", 2)[0], resp.Status)
	}
	return body, nil
}

// list reads every page of a list.
func list[T any](ctx context.Context, api API, path string) ([]T, error) {
	var all []T
	next := ""
	for {
		q := url.Values{"limit": {"500"}}
		if next != "" {
			q.Set("continue", next)
		}
		raw, err := api.Get(ctx, path+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var page struct {
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
			Items []T `json:"items"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("kubernetes: %s: %w", path, err)
		}
		all = append(all, page.Items...)
		if next = page.Metadata.Continue; next == "" {
			return all, nil
		}
	}
}
