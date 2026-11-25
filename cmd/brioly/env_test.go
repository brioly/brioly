package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/brioly/brioly/pkg/lifecycle"
)

// KUBECONFIG in the environment is not read, but it adds a warning: tests
// must not depend on whatever the developer's shell has set.
func TestMain(m *testing.M) {
	os.Unsetenv("KUBECONFIG")
	// The end-of-support dates are read from a local server instead of
	// brioly.io, through the same setting a mirror would use.
	dates := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"updated":"2030-01-01","source":"https://dates.example","products":{"nodejs":{"name":"Node.js","cycles":[{"cycle":"22","eol":"2031-04-30","extended":""}]}}}`)
	}))
	os.Setenv(lifecycle.URLEnv, dates.URL)
	code := m.Run()
	dates.Close()
	os.Exit(code)
}
