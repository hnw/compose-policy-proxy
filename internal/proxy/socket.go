package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Listen returns a listener on path. A socket a killed container left behind must not
// block startup, and one in use is never removed, since that would take its address.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := prepare(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("set mode on %s: %w", path, err)
	}
	return l, nil
}

func prepare(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ensureDir(filepath.Dir(path))
		}
		return fmt.Errorf("inspect %s: %w", path, err)
	}

	// A symlink is never removed, because whoever created it could redirect the
	// proxy's socket.
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to remove it", path)
	}
	if info.Mode().IsRegular() || info.IsDir() {
		return fmt.Errorf("%s already exists and is not a socket", path)
	}

	if inUse(path) {
		return fmt.Errorf("another compose-policy-proxy is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

func inUse(path string) bool {
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: other UIDs need directory traversal; socket permissions restrict access
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return nil
}

func Remove(path string) error {
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}
