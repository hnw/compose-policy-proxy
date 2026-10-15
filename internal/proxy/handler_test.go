package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

// These tests drive the handler over a real socket the way a client does, and check
// the two outcomes. The refusal the proxy writes and the request it hands over untouched.

func TestServeHTTPForwardsAnAuthorizedRequest(t *testing.T) {
	socket, upstream := testProxy(t, demoProject())

	resp := do(t, socket, "GET", "/v1.51/version", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"upstream":"answered"`) {
		t.Errorf("the daemon's answer was not relayed: %q", body)
	}
	// The daemon validates a request against the version the client negotiated,
	// so the proxy may not rewrite the path it forwards.
	if got := upstream.last(); got != "/v1.51/version" {
		t.Errorf("the daemon received %q, want the path as the client sent it", got)
	}
}

func TestServeHTTPRefusesWithoutForwarding(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		path    string
		body    string
		message string
	}{
		{
			name: "an endpoint outside the allowlist", method: "POST", path: "/v1.51/containers/abc/exec",
			message: `compose-policy-proxy: docker API endpoint "/containers/abc/exec" is not allowed`,
		},
		{
			name: "a field the compose file does not declare", method: "POST", path: "/v1.51/containers/create",
			body: `{"Image":"alpine:3.20","User":"root","HostConfig":{"NetworkMode":"demo_frontend"},` +
				`"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`,
			message: `compose-policy-proxy: service "app": Config.User: compose declares "", found "root"`,
		},
		{
			name: "a body the policy cannot decode", method: "POST", path: "/v1.51/containers/create",
			body:    `{"HostConfig":{"SomeNewPrivilegeField":true}}`,
			message: `compose-policy-proxy: container create request cannot be decoded: json: unknown field "SomeNewPrivilegeField"`,
		},
		{
			name: "a request body too large to decide on", method: "POST", path: "/v1.51/containers/create",
			body:    strings.Repeat("x", policy.MaxBodySize+1),
			message: fmt.Sprintf("compose-policy-proxy: request body exceeds %d bytes", policy.MaxBodySize),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			socket, upstream := testProxy(t, demoProject())
			before := upstream.count()

			resp := do(t, socket, tc.method, tc.path, tc.body)
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			body, _ := io.ReadAll(resp.Body)
			var payload map[string]string
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("the refusal is not the documented JSON shape: %v (%q)", err, body)
			}
			if payload["message"] != tc.message {
				t.Errorf("message = %q, want %q", payload["message"], tc.message)
			}
			if upstream.count() != before {
				t.Error("a refused request reached the daemon")
			}
		})
	}
}

func TestServeHTTPLogsEachDecision(t *testing.T) {
	var out strings.Builder
	socket, _ := testProxyWithLogger(t, demoProject(), slog.NewTextHandler(&out, nil))

	ops := []struct{ method, path, body string }{
		{"GET", "/v1.51/version", ""},
		{"POST", "/v1.51/networks/create", `{"Name":"demo_frontend",` +
			`"Labels":{"com.docker.compose.project":"demo","com.docker.compose.network":"frontend"}}`},
		{"GET", "/v1.51/containers/json", ""},
		{"POST", "/v1.51/containers/abc/exec", ""},
		{"POST", "/v1.51/containers/create", `{"Image":"alpine:3.20","User":"root",` +
			`"HostConfig":{"NetworkMode":"demo_frontend"},"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`},
	}
	for _, op := range ops {
		resp := do(t, socket, op.method, op.path, op.body)
		_ = resp.Body.Close()
	}

	log := out.String()
	for _, want := range []string{
		"allowed=true",
		"endpoint=/version",
		"allowed=false",
		"endpoint=/containers/json",
		// A denial over a field names it, a denial with no field to name carries no attribute.
		"endpoint=/containers/create",
		"field=Config.User",
		// A network create matched a Compose key rather than a service.
		"endpoint=/networks/create network=frontend",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("the decision log does not contain %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "reason=") {
		t.Errorf("the decision log still classifies denials by reason:\n%s", log)
	}
	if strings.Contains(log, "endpoint=/networks/create service=") {
		t.Errorf("a network key is recorded as a service name:\n%s", log)
	}
}

// A name filter is an unanchored regular expression on the Engine, so the proxy pins
// it to the single declared name. Every other query parameter travels as it arrived.
func TestServeHTTPForwardsThePinnedListFilter(t *testing.T) {
	socket, upstream := testProxy(t, demoProject())

	resp := do(t, socket, "GET", `/v1.51/networks?filters={"name":{"demo_frontend":true}}`, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200: %s", resp.StatusCode, payload)
	}
	want := "/v1.51/networks?filters=" + url.QueryEscape(`{"name":["^demo_frontend$"]}`)
	if got := upstream.last(); got != want {
		t.Errorf("the daemon received %q, want the pinned filter %q", got, want)
	}

	// A list scoped by label has nothing to pin, so its query is forwarded whole.
	path := `/v1.51/containers/json?all=1&filters={"label":{"com.docker.compose.project=demo":true}}`
	resp = do(t, socket, "GET", path, "")
	defer func() { _ = resp.Body.Close() }()
	if got := upstream.last(); got != path {
		t.Errorf("the daemon received %q, want the query as the client sent it", got)
	}
}

// A query ParseQuery cannot fully parse would be silently trimmed if rebuilt, so the
// proxy refuses it instead of forwarding a request the client did not send.
func TestServeHTTPDoesNotRebuildAMalformedQuery(t *testing.T) {
	socket, upstream := testProxy(t, demoProject())
	before := upstream.count()

	resp := do(t, socket, "GET", `/v1.51/networks?filters={"name":{"demo_frontend":true}}&%ZZ=1`, "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if payload, _ := io.ReadAll(resp.Body); !strings.Contains(string(payload), "query cannot be parsed") {
		t.Errorf("expected the refusal to name the query, got %q", payload)
	}
	if upstream.count() != before {
		t.Error("a request with a malformed query reached the daemon")
	}
}

func TestServeHTTPHidesAComposeSecret(t *testing.T) {
	const secret = "S3cr3t-compose-only"
	project := demoProject()
	app := project.Services["app"]
	app.StorageOpt = types.Mapping{"type": "nfs", "o": secret}
	project.Services["app"] = app

	var out strings.Builder
	socket, _ := testProxyWithLogger(t, project, slog.NewTextHandler(&out, nil))
	resp := do(t, socket, "POST", "/v1.51/containers/create",
		`{"Image":"alpine:3.20","HostConfig":{"NetworkMode":"demo_frontend",`+
			`"StorageOpt":{"type":"nfs","o":"other"}},`+
			`"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "HostConfig.StorageOpt") ||
		!strings.Contains(out.String(), "field=HostConfig.StorageOpt") {
		t.Fatalf("the refusal is not about the storage options:\n%s\n%s", body, out.String())
	}
	if strings.Contains(string(body), secret) || strings.Contains(out.String(), secret) {
		t.Errorf("%q reached the client or the log:\n%s\n%s", secret, body, out.String())
	}
}

func demoProject() *types.Project {
	return &types.Project{
		Name:       "demo",
		WorkingDir: "/opt/app",
		Networks:   types.Networks{"frontend": {Name: "demo_frontend"}},
		Services: types.Services{"app": {
			Name:     "app",
			Image:    "alpine:3.20",
			Networks: map[string]*types.ServiceNetworkConfig{"frontend": {}},
		}},
	}
}

type ownedContainers struct{}

func (ownedContainers) InspectContainer(_ context.Context, id string) (container.InspectResponse, error) {
	if id != "abc" {
		return container.InspectResponse{}, errors.New("no such container")
	}
	return container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			HostConfig: &container.HostConfig{NetworkMode: "demo_frontend"},
		},
		Config: &container.Config{
			Image: "alpine:3.20",
			Labels: map[string]string{
				policy.LabelProject: "demo",
				policy.LabelService: "app",
			},
		},
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{"demo_frontend": {}},
		},
	}, nil
}

func testProxy(t *testing.T, project *types.Project) (string, *daemon) {
	t.Helper()
	return testProxyWith(t, project, newDaemon(t, ""), slog.NewTextHandler(io.Discard, nil))
}

func testProxyWithLogger(t *testing.T, project *types.Project, handler slog.Handler) (string, *daemon) {
	t.Helper()
	return testProxyWith(t, project, newDaemon(t, ""), handler)
}

func testProxyWith(t *testing.T, project *types.Project, upstream *daemon, handler slog.Handler) (string, *daemon) {
	t.Helper()
	authz, err := policy.New(policy.Config{
		Project:    project,
		DockerHost: upstream.socket,
		Listen:     upstream.socket,
		Engine:     ownedContainers{},
	})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	p := New(Config{
		Policy:     authz,
		DockerHost: upstream.socket,
		Logger:     slog.New(handler),
	})

	// The proxy is served over a Unix socket in production, so it is here too. A hijacked
	// stream cannot be modelled by a ResponseWriter alone.
	srv := httptest.NewUnstartedServer(p)
	if err := srv.Listener.Close(); err != nil {
		t.Fatalf("close placeholder listener: %v", err)
	}
	socket := listenUnix(t, filepath.Join(shortTempDir(t), "proxy.sock"))
	srv.Listener = socket
	srv.Start()
	t.Cleanup(srv.Close)
	return socket.Addr().String(), upstream
}

type daemon struct {
	socket string

	mu    sync.Mutex
	paths []string
}

// newDaemon is an Engine speaking the given API version, or one that says nothing about
// it when apiVersion is empty.
func newDaemon(t *testing.T, apiVersion string) *daemon {
	t.Helper()
	d := &daemon{}
	l := listenUnix(t, filepath.Join(shortTempDir(t), "upstream.sock"))
	d.socket = l.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.paths = append(d.paths, r.URL.RequestURI())
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if apiVersion != "" {
			w.Header().Set("Ostype", "linux")
			switch {
			case strings.HasSuffix(r.URL.Path, "/_ping"):
				w.Header().Set("API-Version", apiVersion)
				_, _ = w.Write([]byte("OK"))
				return
			case strings.HasSuffix(r.URL.Path, "/version"):
				w.Header().Set("API-Version", apiVersion)
				_, _ = w.Write([]byte(`{"Version":"29.0.1","ApiVersion":"` + apiVersion +
					`","MinAPIVersion":"1.24","FieldANewerEngineAdded":{"nested":true}}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"upstream":"answered"}`))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d
}

func (d *daemon) last() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.paths) == 0 {
		return ""
	}
	return d.paths[len(d.paths)-1]
}

func (d *daemon) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.paths)
}

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen on %s: %v", path, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func do(t *testing.T, socket, method, path, body string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "http://docker"+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}
