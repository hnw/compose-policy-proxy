// Package e2e drives real `docker compose run` traffic through the proxy against a
// real Docker Engine. See docs/development.md.
package e2e

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
)

// testImage is pinned so the suite does not depend on whatever "latest" tags.
const testImage = "alpine:3.20"

type project struct {
	t           *testing.T
	dir         string
	name        string
	composeYAML string
}

// The project name is the one Compose infers, so two tests never collide on
// Engine resources.
func newProject(t *testing.T, composeYAML string, files map[string]string) *project {
	t.Helper()
	dir := projectTempDir(t)
	p := &project{
		t:           t,
		dir:         dir,
		name:        projectName(dir),
		composeYAML: composeYAML,
	}
	if err := writeFile(p.absolutePath("compose.yaml"), composeYAML); err != nil {
		t.Fatalf("write compose file: %v", err)
	}
	for rel, content := range files {
		if err := writeFile(filepath.Join(p.dir, rel), content); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	p.name = p.loadProject(t).Name
	return p
}

func projectName(dir string) string {
	base := filepath.Base(dir)
	base = strings.NewReplacer("/", "-", "_", "-").Replace(base)
	if len(base) > 20 {
		base = base[len(base)-20:]
	}
	return "cpp" + base
}

func (p *project) absolutePath(parts ...string) string {
	return filepath.Join(append([]string{p.dir}, parts...)...)
}

func (p *project) loadProject(t *testing.T) *types.Project {
	t.Helper()
	opts, err := cli.NewProjectOptions(nil,
		cli.WithWorkingDirectory(p.dir),
		cli.WithOsEnv,
		cli.WithDotEnv,
		cli.WithConfigFileEnv,
		cli.WithDefaultConfigPath,
	)
	if err != nil {
		t.Fatalf("project options: %v", err)
	}
	proj, err := opts.LoadProject(context.Background())
	if err != nil {
		t.Fatalf("load project: %v", err)
	}
	proj.WorkingDir = p.dir
	return proj
}

func (p *project) cleanup(t *testing.T) {
	t.Helper()
	script := fmt.Sprintf(`
docker ps -aq --filter label=com.docker.compose.project=%[1]s | xargs -r docker rm -f >/dev/null 2>&1
docker network ls -q --filter label=com.docker.compose.project=%[1]s | xargs -r docker network rm >/dev/null 2>&1
docker volume ls -q --filter label=com.docker.compose.project=%[1]s | xargs -r docker volume rm >/dev/null 2>&1
`, p.name)
	cmd := exec.Command("sh", "-c", script)
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+dockerHost(t))
	_ = cmd.Run()
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

var proxyBinary string

type harness struct {
	t          *testing.T
	project    *project
	proxy      *proxyProcess
	socket     string
	dockerHost string
}

// proxyProcess runs the proxy as a real process so the tests exercise its CLI
// and signals.
type proxyProcess struct {
	logPath  string
	cmd      *exec.Cmd
	stopOnce sync.Once
}

func startProxy(t *testing.T, p *project, extraArgs ...string) *harness {
	t.Helper()
	return startProxyWithUpstream(t, p, dockerHost(t), extraArgs...)
}

func startProxyAtSocket(t *testing.T, p *project, socket string, extraArgs ...string) *harness {
	t.Helper()
	return launchProxy(t, p, socket, dockerHost(t), extraArgs...)
}

// startProxyWithUpstream launches the proxy against a chosen upstream socket, which
// lets a test observe exactly what the proxy forwards.
func startProxyWithUpstream(t *testing.T, p *project, upstream string, extraArgs ...string) *harness {
	t.Helper()
	dir := shortTempDir(t)
	return launchProxy(t, p, filepath.Join(dir, "docker.sock"), upstream, extraArgs...)
}

func launchProxy(t *testing.T, p *project, socket, upstream string, extraArgs ...string) *harness {
	t.Helper()
	logPath := filepath.Join(filepath.Dir(socket), "proxy.log")

	args := append([]string{
		"--listen", socket,
		"--docker-host", upstream,
		"--log-format", "text",
	}, extraArgs...)

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create proxy log: %v", err)
	}
	cmd := exec.Command(proxyBinary, args...)
	cmd.Dir = p.dir
	// DOCKER_HOST is removed because the application points it at the proxy and the
	// proxy's own Docker client would otherwise talk to itself.
	cmd.Env = withoutEnv(os.Environ(), "DOCKER_HOST")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	proc := &proxyProcess{logPath: logPath, cmd: cmd}
	t.Cleanup(func() { proc.stop() })
	waitForSocket(t, socket)
	// Wait for the proxy to finish loading its project so the first request cannot race start-up.
	waitForLog(t, proc, "listening")

	return &harness{
		t:          t,
		project:    p,
		proxy:      proc,
		socket:     socket,
		dockerHost: upstream,
	}
}

// restart proves ownership cannot come from proxy memory, since nothing carries over.
func (h *harness) restart() *harness {
	h.t.Helper()
	h.proxy.stop()
	return startProxy(h.t, h.project)
}

func (p *proxyProcess) stop() {
	p.stopOnce.Do(func() {
		if p.cmd.Process == nil {
			return
		}
		_ = p.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = p.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			<-done
		}
	})
}

func (p *proxyProcess) log(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(p.logPath)
	if err != nil {
		t.Fatalf("read proxy log: %v", err)
	}
	return string(data)
}

func (p *proxyProcess) requireLogContains(t *testing.T, want string) {
	t.Helper()
	if !strings.Contains(p.log(t), want) {
		t.Fatalf("proxy log does not contain %q\nlog:\n%s", want, p.log(t))
	}
}

func (p *proxyProcess) requireLogOmits(t *testing.T, unwanted string) {
	t.Helper()
	if strings.Contains(p.log(t), unwanted) {
		t.Fatalf("proxy log leaked %q\nlog:\n%s", unwanted, p.log(t))
	}
}

// A temp dir nested under a long per-user path can exceed the sockaddr limit, which
// makes binding fail with an error unrelated to the code under test.
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

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proxy socket %s never appeared", path)
}

func waitForLog(t *testing.T, p *proxyProcess, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(p.log(t), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("proxy log never mentioned %q\nlog:\n%s", want, p.log(t))
}

func (h *harness) runWithInput(stdin string, args ...string) (string, error) {
	h.t.Helper()
	return h.composeWithInput(stdin, append([]string{"run"}, args...)...)
}

// compose runs any compose command through the proxy, for the workflows that address
// containers Compose created rather than a new one-off container.
func (h *harness) compose(args ...string) (string, error) {
	h.t.Helper()
	return h.composeWithInput("", args...)
}

func (h *harness) composeWithInput(stdin string, args ...string) (string, error) {
	h.t.Helper()
	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Dir = h.project.dir
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.socket)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func (h *harness) mustRun(args ...string) string {
	h.t.Helper()
	return h.mustCompose(append([]string{"run"}, args...)...)
}

func (h *harness) mustCompose(args ...string) string {
	h.t.Helper()
	out, err := h.compose(args...)
	if err != nil {
		h.t.Fatalf("docker compose %s failed: %v\noutput:\n%s\nproxy log:\n%s",
			strings.Join(args, " "), err, out, h.proxy.log(h.t))
	}
	return out
}

// followCompose starts a compose command that keeps running, for the streams a client
// follows. `received` reports what the client has received, `ended` waits briefly and
// then reports whether the command ended by itself, and `stop` ends it deliberately.
func (h *harness) followCompose(
	args ...string,
) (received func() string, ended func() (bool, error), stop func()) {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, args...)...)
	cmd.Dir = h.project.dir
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.socket)
	out := &syncBuffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		cancel()
		h.t.Fatalf("start docker compose %s: %v", strings.Join(args, " "), err)
	}
	var waitErr error
	done := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	return out.String,
		func() (bool, error) {
			select {
			case <-done:
				return true, waitErr
			case <-time.After(2 * time.Second):
				return false, nil
			}
		},
		func() {
			cancel()
			<-done
		}
}

// syncBuffer collects what a running command writes while another goroutine reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startedAt reports when the Engine last started a container, so that a restart is shown
// as an effect on the container rather than as a command that returned.
func (h *harness) startedAt(t *testing.T, id string) string {
	t.Helper()
	cmd := exec.Command("docker", "inspect", "--format", "{{.State.StartedAt}}", id)
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.dockerHost)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("inspect when the container started: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// composeOnEngine runs docker compose against the real Engine rather than the
// proxy, which is how the containers the proxy later has to judge come to exist.
func (h *harness) composeOnEngine(args ...string) string {
	h.t.Helper()
	cmd := exec.Command("docker", append([]string{"compose"}, args...)...)
	cmd.Dir = h.project.dir
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.dockerHost)
	out, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("docker compose %s failed on the engine: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// mustRunOnEngine runs a docker command against the real Engine, for the state a
// test needs to exist but that Compose should not create.
func mustRunOnEngine(t *testing.T, host string, args ...string) {
	t.Helper()
	cmd := exec.Command("docker", args...)
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+host)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (h *harness) mustDeny(args ...string) string {
	h.t.Helper()
	return h.mustDenyCompose(append([]string{"run"}, args...)...)
}

func (h *harness) mustDenyCompose(args ...string) string {
	h.t.Helper()
	out, err := h.compose(args...)
	if err == nil {
		h.t.Fatalf("docker compose %s unexpectedly succeeded\noutput:\n%s", strings.Join(args, " "), out)
	}
	if !strings.Contains(out, "compose-policy-proxy") {
		h.t.Fatalf("docker compose %s failed for an unrelated reason\noutput:\n%s\nproxy log:\n%s",
			strings.Join(args, " "), out, h.proxy.log(h.t))
	}
	return out
}

func dockerHost(t *testing.T) string {
	t.Helper()
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "docker", "context", "inspect",
			"--format", "{{.Endpoints.docker.Host}}").Output()
		if err != nil {
			t.Skipf("no Docker Engine available: %v", err)
		}
		host = strings.TrimSpace(string(out))
	}
	host = strings.TrimPrefix(host, "unix://")
	if host == "" {
		t.Skip("no Docker Engine socket available")
	}
	return host
}

func proxyClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func doRequest(t *testing.T, socket, method, path, body string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "http://docker"+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := proxyClient(socket).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	var sb strings.Builder
	if _, err := io.Copy(&sb, resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return sb.String()
}

func urlEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func projectContainers(t *testing.T, p *project) []string {
	t.Helper()
	cmd := exec.Command("docker", "ps", "-a", "--filter",
		"label=com.docker.compose.project="+p.name, "--format", "{{.ID}}")
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+dockerHost(t))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list project containers: %v", err)
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" {
			ids = append(ids, line)
		}
	}
	return ids
}

func (p *project) containerForService(t *testing.T, service string) string {
	t.Helper()
	cmd := exec.Command("docker", "ps", "-aq", "--filter",
		"label=com.docker.compose.project="+p.name,
		"--filter", "label=com.docker.compose.service="+service)
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+dockerHost(t))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list containers of service %s: %v", service, err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		t.Fatalf("expected exactly one container for service %s, got %v", service, ids)
	}
	return ids[0]
}

type recordingDaemon struct {
	socket string
	mu     sync.Mutex
	seen   []string
}

func newRecordingDaemon(t *testing.T, handler http.Handler) *recordingDaemon {
	t.Helper()
	r := &recordingDaemon{socket: filepath.Join(shortTempDir(t), "upstream.sock")}
	l, err := net.Listen("unix", r.socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if handler == nil {
		// The proxy reads the Engine's API version at startup, so the negotiation
		// endpoints answer as an Engine would rather than as an empty object.
		handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.HasSuffix(req.URL.Path, "/_ping"):
				w.Header().Set("API-Version", "1.51")
				_, _ = w.Write([]byte("OK"))
			case strings.HasSuffix(req.URL.Path, "/version"):
				_, _ = w.Write([]byte(`{"ApiVersion":"1.51","MinAPIVersion":"1.24"}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		})
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.URL.RequestURI())
		r.mu.Unlock()
		handler.ServeHTTP(w, req)
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return r
}

func (r *recordingDaemon) paths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func withEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			out := append([]string(nil), env...)
			out[i] = prefix + value
			return out
		}
	}
	return append(append([]string(nil), env...), prefix+value)
}

func withoutEnv(env []string, key string) []string {
	prefix := key + "="
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func startSecondProxyExpectingFailure(t *testing.T, p *project, socket string) string {
	t.Helper()
	cmd := exec.Command(proxyBinary, "--listen", socket, "--docker-host", dockerHost(t))
	cmd.Dir = p.dir
	cmd.Env = withoutEnv(os.Environ(), "DOCKER_HOST")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the proxy unexpectedly started on %s", socket)
	}
	return string(out)
}

// detachAndLeaveRunning starts a container through the proxy and leaves it running
// for a later step to act on.
func detachAndLeaveRunning(t *testing.T, h *harness, p *project, args ...string) {
	t.Helper()
	if len(args) == 0 {
		args = []string{"app"}
	}
	cmd := exec.Command("docker", append([]string{"compose", "run", "-d"}, args...)...)
	cmd.Dir = p.dir
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.socket)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("detached run failed: %v\n%s", err, out)
	}
}

// On macOS the default temp dir under /var/folders is not shared with the Linux VM
// running the Engine, so a bind source resolved there would mount an empty directory.
func hostVisibleTempRoot() string {
	hostVisibleRootOnce.Do(func() { hostVisibleRoot = findHostVisibleTempRoot() })
	return hostVisibleRoot
}

var (
	hostVisibleRootOnce sync.Once
	hostVisibleRoot     string
)

func findHostVisibleTempRoot() string {
	candidates := []string{os.TempDir(), "/tmp", "/private/tmp"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	marker := "compose-policy-proxy-e2e-marker"
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if !isHostVisible(dir, marker) {
			continue
		}
		return dir
	}
	// Fall back to the default so the tests report the real failure instead of hiding it here.
	return os.TempDir()
}

func isHostVisible(dir, marker string) bool {
	probe := filepath.Join(dir, marker)
	if err := writeFile(probe, marker); err != nil {
		return false
	}
	defer func() { _ = os.Remove(probe) }()
	cmd := exec.Command("docker", "run", "--rm",
		"-v", dir+":/probe:ro", testImage, "cat", "/probe/"+marker)
	out, err := cmd.CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == marker
}

func projectTempDir(t *testing.T) string {
	t.Helper()
	root := hostVisibleTempRoot()
	dir, err := os.MkdirTemp(root, "cpp")
	if err != nil {
		t.Fatalf("create project dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
