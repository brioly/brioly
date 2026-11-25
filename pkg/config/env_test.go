package config

import (
	"os"
	"testing"
)

// KUBECONFIG in the environment is not read, but it adds a warning: tests
// must not depend on whatever the developer's shell has set.
func TestMain(m *testing.M) {
	os.Unsetenv("KUBECONFIG")
	os.Exit(m.Run())
}
