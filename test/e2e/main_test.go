package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cpp-build")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: create build dir:", err)
		os.Exit(1)
	}
	// os.Exit skips the deferred cleanup, so every way out of this function removes
	// the build directory first.
	exit := func(code int) {
		_ = os.RemoveAll(dir)
		os.Exit(code)
	}

	binary := filepath.Join(dir, "compose-policy-proxy")
	cmd := exec.Command("go", "build", "-o", binary, "../../cmd/compose-policy-proxy")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: build proxy:", err)
		exit(1)
	}
	proxyBinary = binary

	// The whole suite is meaningless without a Docker Engine, so check once here.
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: docker not found; skipping")
		exit(0)
	}
	out, err := exec.Command("docker", "compose", "version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "version") {
		fmt.Fprintln(os.Stderr, "e2e: docker compose plugin not available; skipping")
		exit(0)
	}
	if out, err := exec.Command("docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: no reachable Docker Engine (%s): skipping\n", strings.TrimSpace(string(out)))
		exit(0)
	}

	exit(m.Run())
}
