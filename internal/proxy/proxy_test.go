package proxy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamingEndpoint(t *testing.T) {
	if !isStreamingEndpoint("/containers/{id}/attach") {
		t.Error("attach must be forwarded as a hijacked stream")
	}
	for _, endpoint := range []string{"/containers/{id}/json", "/containers/create", "/containers/{id}/wait"} {
		if isStreamingEndpoint(endpoint) {
			t.Errorf("%s is not a hijacked stream", endpoint)
		}
	}
}

// shortTempDir needs a path that fits a Unix socket address, which a deep macOS
// temp directory does not.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cpp")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	if len(filepath.Join(dir, "docker.sock")) > 90 {
		if alt, altErr := os.MkdirTemp("/tmp", "cpp"); altErr == nil {
			_ = os.RemoveAll(dir)
			dir = alt
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestListenCreatesSocket(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "nested", "docker.sock")
	l, err := Listen(path, 0o660)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %#o, want 0660", info.Mode().Perm())
	}
}

func TestListenRefusesSocketInUse(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "docker.sock")
	first, err := Listen(path, 0o660)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	defer func() { _ = first.Close() }()

	if _, err := Listen(path, 0o660); err == nil {
		t.Fatal("a second proxy took over a socket that was in use")
	} else if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "docker.sock")
	first, err := Listen(path, 0o660)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	// Leave the socket file behind with nothing listening, as a killed container would.
	first.(*netUnixListener).SetUnlinkOnClose(false)
	_ = first.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected a stale socket file: %v", err)
	}

	second, err := Listen(path, 0o660)
	if err != nil {
		t.Fatalf("a stale socket should be replaced: %v", err)
	}
	defer func() { _ = second.Close() }()
}

func TestListenRefusesNonSocket(t *testing.T) {
	dir := shortTempDir(t)

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(regular, 0o660); err == nil {
		t.Error("a regular file was accepted as a socket path")
	}
	if _, err := os.Stat(regular); err != nil {
		t.Error("the proxy deleted a regular file, which it must never do")
	}

	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(symlink, 0o660); err == nil {
		t.Error("a symlink was accepted as a socket path")
	}
}

func TestRemoveIgnoresMissingSocket(t *testing.T) {
	if err := Remove(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Errorf("removing an absent socket should be a no-op, got %v", err)
	}
}

type netUnixListener = net.UnixListener
