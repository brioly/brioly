package config

import (
	"os"
	"testing"
)

// KUBECONFIG in the environment turns the Kubernetes source on. Tests must
// not read whatever cluster the developer's shell points at.
func TestMain(m *testing.M) {
	os.Unsetenv("KUBECONFIG")
	os.Exit(m.Run())
}
