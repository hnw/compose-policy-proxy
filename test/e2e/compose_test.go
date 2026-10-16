package e2e

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

const baseCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo HELLO-FROM-RUN; echo answer=$(cat /app/config/answer)"]
    working_dir: /app
    environment:
      GREETING: hello
    volumes:
      - ./config:/app/config:ro
      - cache:/cache
    networks:
      - frontend
    ports:
      - "18080:80"
      - "127.0.0.1:18090:90/udp"
networks:
  frontend:
volumes:
  cache:
`

func newBaseProject(t *testing.T) *project {
	t.Helper()
	p := newProject(t, render(baseCompose, testImage), map[string]string{
		"config/answer": "42",
	})
	t.Cleanup(func() { p.cleanup(t) })
	return p
}

func render(tmpl, image string) string {
	return strings.ReplaceAll(tmpl, "%IMAGE%", image)
}

func TestRunBasic(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	out := h.mustRun("--rm", "app")
	if !strings.Contains(out, "answer=42") {
		t.Errorf("expected the bind mount to be readable, got:\n%s", out)
	}
	h.proxy.requireLogContains(t, "endpoint=/volumes/create")
	h.proxy.requireLogContains(t, "endpoint=/networks/create")
	h.proxy.requireLogContains(t, "endpoint=/containers/create")
	h.proxy.requireLogContains(t, "service=app")
}

func TestRunCommandOverride(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo ORIGINAL-COMMAND"]
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "app", "echo", "OVERRIDDEN-COMMAND")
	if !strings.Contains(out, "OVERRIDDEN-COMMAND") {
		t.Errorf("expected the overridden command to run, got:\n%s", out)
	}
	if strings.Contains(out, "ORIGINAL-COMMAND") {
		t.Errorf("the Compose command should have been replaced, got:\n%s", out)
	}
}

func TestRunStdin(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["cat"]
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out, err := h.runWithInput("piped-through-the-proxy\n", "--rm", "-T", "app")
	if err != nil {
		t.Fatalf("run with stdin failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "piped-through-the-proxy") {
		t.Errorf("stdin did not reach the container, got:\n%s", out)
	}
}

func TestRunEnvironmentOverride(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo GREETING=$$GREETING"]
    environment:
      GREETING: from-compose
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "-e", "GREETING=from-cli", "app")
	if !strings.Contains(out, "GREETING=from-cli") {
		t.Errorf("expected the CLI environment override to win, got:\n%s", out)
	}
}

func TestRunServicePorts(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "-P", "app")
	if !strings.Contains(out, "HELLO-FROM-RUN") {
		t.Errorf("run with --service-ports failed, got:\n%s", out)
	}
}

func TestWaitAndCleanup(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	h.mustRun("--rm", "app")
	h.proxy.requireLogContains(t, "endpoint=/containers/{id}/wait")
	if ids := projectContainers(t, p); len(ids) != 0 {
		t.Errorf("--rm should have removed the container, still present: %v", ids)
	}
}

func TestOwnershipSurvivesRestart(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "sleep 600"]
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	detachAndLeaveRunning(t, h, p)
	ids := projectContainers(t, p)
	if len(ids) == 0 {
		t.Fatal("expected a container to exist")
	}

	// Ownership can only come from the Engine, since nothing carries over to the new process.
	h2 := h.restart()
	resp := doRequest(t, h2.socket, "GET", "/containers/"+ids[0]+"/json", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the restarted proxy did not recognise its own container: %d %s",
			resp.StatusCode, readBody(t, resp))
	}
}

// `start` and `stop` address a container Compose created earlier, and the proxy does
// not create service containers, so the host makes one exist first.
const startStopCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "sleep 600"]
`

func newStartStopProject(t *testing.T) *project {
	t.Helper()
	p := newProject(t, render(startStopCompose, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	return p
}

func TestStartAndStopThroughTheProxy(t *testing.T) {
	p := newStartStopProject(t)
	h := startProxy(t, p)

	h.composeOnEngine("create", "app")
	id := p.containerForService(t, "app")

	h.mustCompose("start", "app")
	if !h.isRunning(id) {
		t.Fatal("docker compose start did not start the container")
	}
	h.mustCompose("stop", "app")
	if h.isRunning(id) {
		t.Fatal("docker compose stop did not stop the container")
	}
}

func TestStartAndStopAreRefusedWithoutTheirCommand(t *testing.T) {
	p := newStartStopProject(t)
	h := startProxy(t, p, "--allow-command=run")

	h.composeOnEngine("create", "app")
	id := p.containerForService(t, "app")

	if out := h.mustDenyCompose("start", "app"); !strings.Contains(out, "compose start is not available") {
		t.Errorf("expected the refusal to name the command, got:\n%s", out)
	}
	if h.isRunning(id) {
		t.Fatal("a refused start started the container anyway")
	}

	h.composeOnEngine("start", "app")
	h.mustDenyCompose("stop", "app")
	if !h.isRunning(id) {
		t.Fatal("a refused stop stopped the container anyway")
	}
}

func TestCannotListOutsideProject(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	cases := []struct {
		name   string
		query  string
		expect string
	}{
		{"no filters", "", "carries no filters"},
		{"empty filters", "?filters=%7B%7D", "empty filters"},
		{"filter without the project label",
			"?filters=" + urlEncode(`{"label":{"com.docker.compose.config-hash":true}}`),
			"must filter on com.docker.compose.project"},
		{"filter naming a foreign label",
			"?filters=" + urlEncode(`{"label":{"public=yes":true}}`),
			"must filter on com.docker.compose.project"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, h.socket, "GET", "/containers/json"+tc.query, "")
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("the list request was allowed, but it would expose other projects")
			}
			if body := readBody(t, resp); !strings.Contains(body, tc.expect) {
				t.Fatalf("expected the denial to mention %q, got:\n%s", tc.expect, body)
			}
		})
	}
}

// A name filter is an unanchored regular expression on the Engine, so the bare name
// Compose sends also matches "demo_frontend_other". The proxy pins it to the declared name.
func TestListByNameCannotSeeSimilarlyNamedResources(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	declared := p.loadProject(t)
	cases := []struct {
		kind     string
		path     string
		declared string
		foreign  string
	}{
		{kind: "network", path: "networks", declared: declared.Networks["frontend"].Name},
		{kind: "volume", path: "volumes", declared: declared.Volumes["cache"].Name},
	}
	for i := range cases {
		// A resource of another project whose name contains the declared one.
		cases[i].foreign = cases[i].declared + "_other"
		mustRunOnEngine(t, h.dockerHost, cases[i].kind, "create", cases[i].foreign)
		t.Cleanup(func() {
			mustRunOnEngine(t, h.dockerHost, cases[i].kind, "rm", cases[i].foreign)
		})
	}

	h.mustRun("--rm", "-T", "app")

	for _, tc := range cases {
		filters := urlEncode(`{"name":{"` + tc.declared + `":true}}`)
		resp := doRequest(t, h.socket, "GET", "/"+tc.path+"?filters="+filters, "")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("listing the declared %s was refused: %d %s", tc.kind, resp.StatusCode, body)
		}
		if !strings.Contains(body, tc.declared) {
			t.Errorf("listing %q did not return it:\n%s", tc.declared, body)
		}
		if strings.Contains(body, tc.foreign) {
			t.Errorf("listing %q returned %q, which the project does not declare:\n%s",
				tc.declared, tc.foreign, body)
		}
	}
}

func TestCannotAddressProjectExternalResources(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	for _, path := range []string{
		"/v1.51/volumes/someone-elses-volume",
		"/v1.51/networks/someone-elses-network",
		"/v1.51/images/busybox:latest/json",
	} {
		resp := doRequest(t, h.socket, "GET", path, "")
		if resp.StatusCode == http.StatusOK {
			t.Errorf("GET %s was allowed for a resource outside the project", path)
		}
		_ = resp.Body.Close()
	}
}

func TestDeniesSecuritySensitiveChanges(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["true"]
    user: "1000:1000"
    cap_drop: ["ALL"]
    read_only: true
    volumes:
      - ./data:/data:ro
`, testImage), map[string]string{"data/x": "x"})
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"user override", []string{"--rm", "-T", "--user", "root", "app"}, "Config.User"},
		{"capability added", []string{"--rm", "-T", "--cap-add", "SYS_ADMIN", "app"}, "HostConfig.CapAdd"},
		{"entrypoint override", []string{"--rm", "-T", "--entrypoint", "/bin/sh", "app"}, "Config.Entrypoint"},
		{"bind mount added", []string{"--rm", "-T", "-v", "/:/host", "app"}, "not declared by compose"},
		{"port published outside compose", []string{"--rm", "-T", "-p", "12345:99", "app"}, "HostConfig.PortBindings"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := h.mustDeny(tc.args...)
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected the denial to mention %q, got:\n%s", tc.want, out)
			}
		})
	}
}

// --cap-drop is the one capability override that grants nothing, because it only removes
// a capability and Compose removes it from cap_add too.
func TestAllowsCapabilityDrops(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo DROPPED-OK"]
    cap_add: ["CHOWN"]
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "--cap-drop", "CHOWN", "app")
	if !strings.Contains(out, "DROPPED-OK") {
		t.Errorf("expected the run to succeed, got:\n%s", out)
	}
}

// No Compose CLI flag can ask for host networking, but a client speaking the Docker
// API directly can, and that is the client this proxy exists for.
func TestDeniesNetworkIsolationEscapes(t *testing.T) {
	// A minimal project, so that the mount comparison does not deny first and
	// mask the network decision under test.
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["true"]
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	cases := []struct {
		name string
		body func(networkName string) []byte
		want string
	}{
		{
			name: "host networking",
			body: func(string) []byte {
				return []byte(`{"Image":"` + testImage + `","Cmd":["true"],"Labels":` +
					`{"com.docker.compose.project":"` + p.name + `","com.docker.compose.service":"app",` +
					`"com.docker.compose.oneoff":"True"},` +
					`"HostConfig":{"NetworkMode":"host"}}`)
			},
			want: "HostConfig.NetworkMode",
		},
		{
			name: "another container's namespace",
			body: func(string) []byte {
				return []byte(`{"Image":"` + testImage + `","Cmd":["true"],"Labels":` +
					`{"com.docker.compose.project":"` + p.name + `","com.docker.compose.service":"app",` +
					`"com.docker.compose.oneoff":"True"},` +
					`"HostConfig":{"NetworkMode":"container:a-victim"}}`)
			},
			want: "HostConfig.NetworkMode",
		},
		{
			name: "publish all ports",
			body: func(networkName string) []byte {
				return buildCreateRequest(t, p, networkName, nil,
					map[string]any{"PublishAllPorts": true}, nil)
			},
			want: "HostConfig.PublishAllPorts",
		},
		{
			name: "an undeclared network",
			body: func(networkName string) []byte {
				return []byte(`{"Image":"` + testImage + `","Cmd":["true"],"Labels":` +
					`{"com.docker.compose.project":"` + p.name + `","com.docker.compose.service":"app",` +
					`"com.docker.compose.oneoff":"True"},` +
					`"HostConfig":{"NetworkMode":"` + networkName + `"},` +
					`"NetworkingConfig":{"EndpointsConfig":{"` + networkName + `":{},"someone_elses":{}}}}`)
			},
			want: "NetworkingConfig.EndpointsConfig",
		},
	}
	networkName := p.loadProject(t).Name + "_default"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := doRequest(t, h.socket, "POST", "/containers/create", string(tc.body(networkName)))
			if resp.StatusCode == http.StatusOK || resp.StatusCode < 300 {
				t.Fatalf("the request was accepted, but %s must be refused", tc.name)
			}
			out := readBody(t, resp)
			if !strings.Contains(out, "compose-policy-proxy") {
				t.Fatalf("the daemon answered rather than the proxy: %s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected the denial to mention %q, got:\n%s", tc.want, out)
			}
		})
	}
}

func TestDeniesHostConfigBinds(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	// The request mirrors what Docker Compose sends for this project, with a
	// single extra bind entry, so that the denial can only be about that entry.
	network := p.loadProject(t).Name + "_default"
	body := `{"Image":"` + testImage + `","Cmd":["true"],"WorkingDir":"/app","Labels":` +
		`{"com.docker.compose.project":"` + p.name + `","com.docker.compose.service":"app",` +
		`"com.docker.compose.oneoff":"True"},` +
		`"HostConfig":{"NetworkMode":"` + network + `","Binds":["/:/host:rw"]},` +
		`"NetworkingConfig":{"EndpointsConfig":{"` + network + `":{"Aliases":null}}}}`
	resp := doRequest(t, h.socket, "POST", "/containers/create", body)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a create request declaring HostConfig.Binds was allowed")
	}
	out := readBody(t, resp)
	if !strings.Contains(out, "HostConfig.Binds") || !strings.Contains(out, "not declared by compose") {
		t.Fatalf("expected the bind entry to be refused as undeclared, got:\n%s", out)
	}
}

func TestDeniesEndpointsOutsideAllowlist(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	id := strings.Repeat("a", 64)
	denied := []struct{ method, path string }{
		{"POST", "/containers/" + id + "/exec"},
		{"POST", "/v1.51/build"},
		{"POST", "/v1.51/images/prune"},
		{"GET", "/v1.51/events"},
		{"POST", "/v1.51/networks/" + p.name + "_frontend/disconnect"},
		{"DELETE", "/v1.51/volumes/" + p.name + "_cache"},
		{"POST", "/v1.51/services/create"},
		{"PUT", "/containers/" + id + "/update"},
	}
	for _, tc := range denied {
		resp := doRequest(t, h.socket, tc.method, tc.path, "")
		if resp.StatusCode == http.StatusOK {
			t.Errorf("%s %s was allowed but is not in the allowlist", tc.method, tc.path)
		}
		_ = resp.Body.Close()
	}
}

func TestDeniesWrongMethodOnAllowlistedPath(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	resp := doRequest(t, h.socket, "DELETE", "/v1.51/networks/create", "")
	if resp.StatusCode == http.StatusOK {
		t.Fatal("DELETE /networks/create was allowed")
	}
	if body := readBody(t, resp); !strings.Contains(body, "method") {
		t.Fatalf("expected a method-related denial, got:\n%s", body)
	}
}

func TestDeniesUnsupportedAPIVersion(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	resp := doRequest(t, h.socket, "GET", "/v9.99/containers/json", "")
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an unrecognised API version was allowed")
	}
	if body := readBody(t, resp); !strings.Contains(body, "API version") {
		t.Fatalf("expected the denial to mention the API version, got:\n%s", body)
	}
}

func TestPreservesAPIVersionPrefix(t *testing.T) {
	p := newBaseProject(t)
	rec := newRecordingDaemon(t, nil)
	h := startProxyWithUpstream(t, p, rec.socket)

	filters := urlEncode(`{"label":{"com.docker.compose.project=` + p.name + `":true}}`)
	resp := doRequest(t, h.socket, "GET", "/v1.41/containers/json?all=1&filters="+filters, "")
	_ = resp.Body.Close()

	want := "/v1.41/containers/json?all=1&filters=" + filters
	if !slices.Contains(rec.paths(), want) {
		t.Fatalf("the upstream never received %q, which kept the client's negotiated API version: %q",
			want, rec.paths())
	}
}

func TestRefusesUnknownRequestField(t *testing.T) {
	p := newBaseProject(t)
	h := startProxy(t, p)

	body := `{"Image":"` + testImage + `","Cmd":["true"],"HostConfig":{"SomeNewPrivilegeField":true}}`
	resp := doRequest(t, h.socket, "POST", "/containers/create", body)
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a create request with an unrecognised field was allowed")
	}
	out := readBody(t, resp)
	if !strings.Contains(out, "cannot be decoded") {
		t.Fatalf("expected a decode failure, got:\n%s", out)
	}
}

func TestDoesNotLogSecrets(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo VALUE=$$TOP_SECRET"]
    environment:
      TOP_SECRET: super-secret-value
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "app")
	if !strings.Contains(out, "VALUE=super-secret-value") {
		t.Fatalf("the run itself failed, got:\n%s", out)
	}
	h.proxy.requireLogOmits(t, "super-secret-value")
}

func TestSocketLifecycle(t *testing.T) {
	p := newBaseProject(t)

	h := startProxy(t, p)
	resp := startSecondProxyExpectingFailure(t, p, h.socket)
	if !strings.Contains(resp, "already listening") {
		t.Fatalf("expected the second proxy to report the socket in use, got:\n%s", resp)
	}

	dir := shortTempDir(t)
	path := dir + "/regular"
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if resp := startSecondProxyExpectingFailure(t, p, path); !strings.Contains(resp, "not a socket") {
		t.Fatalf("expected the regular file to be refused, got:\n%s", resp)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the proxy must not delete a regular file")
	}

	stale := dir + "/stale"
	l, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the socket on disk with nothing listening behind it, as a killed container does.
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = l.Close()
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("expected a stale socket file: %v", err)
	}
	startProxyAtSocket(t, p, stale)
}

// The interesting comparison failures are combinations, so this declares many
// security-sensitive settings at once. A single field is easy to get right.
const richCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo RICH-OK"]
    user: "1000:1000"
    privileged: true
    read_only: true
    cap_add: ["NET_ADMIN", "SYS_TIME"]
    cap_drop: ["MKNOD"]
    group_add: ["2000", "3000"]
    security_opt: ["no-new-privileges:true"]
    devices:
      - "/dev/null:/dev/null"
    device_cgroup_rules: ["c 1:3 mr"]
    sysctls:
      net.ipv4.ip_forward: "1"
    runtime: runc
    ipc: host
    pid: host
    cgroup: host
    userns_mode: host
    hostname: rich-app
    working_dir: /app
    stop_signal: SIGTERM
    stop_grace_period: 5s
    dns: ["10.0.0.53"]
    dns_search: ["example.test"]
    dns_opt: ["ndots:2"]
    extra_hosts:
      - "host.docker.internal:10.0.0.1"
    oom_score_adj: 100
    shm_size: 64m
    logging:
      driver: json-file
      options:
        max-size: "10m"
    ulimits:
      nofile:
        soft: 1024
        hard: 2048
    volumes:
      - ./config:/app/config:ro
      - cache:/cache
      - /tmp/anon-vol
    tmpfs:
      - /tmpmount:size=1m,mode=1777
    networks:
      frontend:
        aliases: ["myalias"]
        ipv4_address: 172.31.0.10
        mac_address: "02:42:ac:1e:00:0a"
        gw_priority: 100
      gwprio:
        gw_priority: 10
    ports:
      - "18080:80"
      - "127.0.0.1:18090:90/udp"
    expose:
      - "9999"
    healthcheck:
      test: ["CMD", "true"]
      interval: 5s
      timeout: 2s
      retries: 3
    environment:
      RICH: "yes"
networks:
  frontend:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br-rich-e2e
    ipam:
      driver: default
      config:
        - subnet: 172.31.0.0/24
          gateway: 172.31.0.1
  gwprio:
    driver: bridge
volumes:
  cache:
    driver: local
`

func TestRunWithRichServiceSettings(t *testing.T) {
	p := newProject(t, render(richCompose, testImage), map[string]string{
		"config/f.txt": "content",
	})
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "app")
	if !strings.Contains(out, "RICH-OK") {
		t.Errorf("expected the container to run, got:\n%s", out)
	}
	h.proxy.requireLogContains(t, "endpoint=/networks/create")
	h.proxy.requireLogContains(t, "endpoint=/volumes/create")
}

// Every field here differs from what the Compose file declares and the request is still
// accepted. TestDeniesSecuritySensitiveChanges shows the other half of the boundary.
func TestForwardsFieldsOutsideV1Scope(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["true"]
`, testImage), nil)
	// The requests below carry the project label, so the project's cleanup
	// finds and removes them.
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	network := p.loadProject(t).Name + "_default"

	cases := []struct {
		name string
		// Neither may contain anything the proxy compares.
		config map[string]any
		host   map[string]any
	}{
		// Class C, availability and resource consumption
		{name: "oom score adj", host: map[string]any{"OomScoreAdj": -1000}},
		{name: "oom kill disable", host: map[string]any{"OomKillDisable": true}},
		{name: "shm size", host: map[string]any{"ShmSize": 536870912}},
		{name: "ulimits", host: map[string]any{
			"Ulimits": []map[string]any{{"Name": "nofile", "Soft": 1048576, "Hard": 1048576}},
		}},
		{name: "memory limit", host: map[string]any{"Memory": 68719476736, "MemorySwap": 68719476736}},
		{name: "cpu limit", host: map[string]any{
			"CpuQuota": 500000, "CpuPeriod": 50000, "NanoCpus": 4000000000, "CpusetCpus": "0-3",
		}},
		{name: "pids limit", host: map[string]any{"PidsLimit": 1048576}},
		{name: "log driver", host: map[string]any{
			"LogConfig": map[string]any{
				"Type":   "syslog",
				"Config": map[string]string{"syslog-address": "tcp://198.51.100.7:514"},
			},
		}},

		// Class D, container internals and lifecycle
		{name: "healthcheck", config: map[string]any{
			"Healthcheck": map[string]any{"Test": []string{"CMD-SHELL", "curl evil.test"}},
		}},
		{name: "stop signal", config: map[string]any{"StopSignal": "SIGKILL"}},
		{name: "stop timeout", config: map[string]any{"StopTimeout": 3600}},
		{name: "hostname", config: map[string]any{"Hostname": "attacker-chosen"}},
		{name: "domain name", config: map[string]any{"Domainname": "attacker.test"}},
		{name: "working directory", config: map[string]any{"WorkingDir": "/host"}},
		{name: "environment", config: map[string]any{"Env": []string{"TOKEN=attacker-supplied"}}},
		{name: "tty", config: map[string]any{"Tty": true, "OpenStdin": true}},
		{name: "init", host: map[string]any{"Init": true}},
		{name: "restart policy", host: map[string]any{
			"RestartPolicy": map[string]any{"Name": "always"},
		}},

		// Class D, general network behaviour
		{name: "dns", host: map[string]any{
			"Dns": []string{"198.51.100.53"}, "DnsSearch": []string{"attacker.test"},
			"DnsOptions": []string{"ndots:2"},
		}},
		{name: "extra hosts", host: map[string]any{
			"ExtraHosts": []string{"metadata.google.internal:169.254.169.254"},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := buildCreateRequest(t, p, network, tc.config, tc.host, nil)
			requireForwarded(t, h.socket, tc.name, body)
		})
	}

	t.Run("endpoint metadata", func(t *testing.T) {
		// Endpoint reachability metadata is class D. It changes how the container
		// is reached inside the network it is already attached to.
		endpoints := map[string]any{
			network: map[string]any{
				"Aliases":    []string{"someone-elses-service"},
				"MacAddress": "02:42:ac:1e:00:0b",
				"GwPriority": 1000,
				"DriverOpts": map[string]string{"attacker": "controlled"},
				"IPAMConfig": map[string]any{
					"IPv4Address":  "172.30.0.99",
					"IPv6Address":  "fd00::99",
					"LinkLocalIPs": []string{"169.254.1.1"},
				},
			},
		}
		requireForwarded(t, h.socket, "endpoint metadata",
			buildCreateRequest(t, p, network, nil, nil, endpoints))
	})
}

// A daemon refusal afterwards proves nothing about the proxy. What is ruled out is
// a denial carrying the proxy's own prefix.
func requireForwarded(t *testing.T, socket, what string, body []byte) {
	t.Helper()
	resp := doRequest(t, socket, "POST", "/containers/create", string(body))
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return
	}
	out := readBody(t, resp)
	if strings.Contains(out, "compose-policy-proxy") {
		t.Errorf("v1 forwards %s, but the proxy refused it: %s", what, out)
	}
}

// buildCreateRequest assembles a create request that is otherwise exactly what Compose
// would send, so a denial can only be about the fields the caller added.
func buildCreateRequest(
	t *testing.T,
	p *project,
	network string,
	config map[string]any,
	hostConfig map[string]any,
	endpoints map[string]any,
) []byte {
	t.Helper()

	merged := map[string]any{"NetworkMode": network}
	for k, v := range hostConfig {
		merged[k] = v
	}
	if endpoints == nil {
		// The service is on the project's default network, so a faithful request declares
		// that endpoint even when the test is not about networking.
		endpoints = map[string]any{network: map[string]any{}}
	}

	req := map[string]any{
		"Image": testImage,
		"Cmd":   []string{"true"},
		"Labels": map[string]string{
			policy.LabelProject: p.name,
			policy.LabelService: "app",
			policy.LabelOneoff:  "True",
		},
		"HostConfig":       merged,
		"NetworkingConfig": map[string]any{"EndpointsConfig": endpoints},
	}
	for k, v := range config {
		req[k] = v
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	return body
}

// The compared mount options in the representations Compose actually chooses. A
// plain bind as a legacy Binds string and a volume with nocopy through the Mount API.
const mountVariantsCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo MOUNTS-OK; test -f /plain/f.txt && test -f /rslave/f.txt && echo BOTH-VISIBLE"]
    volumes:
      - ./cfg:/plain
      - ./cfg:/ro:ro
      - ./cfg:/rslave:rslave
      - ./cfg:/shared
      - vol:/nocopy:nocopy
`

func TestRunWithMountOptionVariants(t *testing.T) {
	p := newProject(t, render(mountVariantsCompose, testImage)+"volumes:\n  vol: {}\n",
		map[string]string{"cfg/f.txt": "content"})
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	out := h.mustRun("--rm", "-T", "app")
	if !strings.Contains(out, "MOUNTS-OK") {
		t.Errorf("expected the container to run, got:\n%s", out)
	}
	if !strings.Contains(out, "BOTH-VISIBLE") {
		t.Errorf("expected the plain and propagated binds to be visible, got:\n%s", out)
	}
}

// Annotations are arbitrary metadata handed to the runtime, so the proxy requires
// an exact match rather than trying to judge them harmless.
func TestDeniesAnnotations(t *testing.T) {
	p := newProject(t, render(`services:
  app:
    image: %IMAGE%
    command: ["true"]
    annotations:
      org.example.declared: "yes"
`, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	network := p.loadProject(t).Name + "_default"

	t.Run("matching annotations", func(t *testing.T) {
		body := buildCreateRequest(t, p, network, nil,
			map[string]any{"Annotations": map[string]string{"org.example.declared": "yes"}}, nil)
		resp := doRequest(t, h.socket, "POST", "/containers/create", string(body))
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			t.Errorf("matching annotations should be accepted: %s", readBody(t, resp))
		}
		_ = resp.Body.Close()
	})

	for _, tc := range []struct {
		name  string
		value map[string]string
	}{
		{"extra annotation", map[string]string{
			"org.example.declared": "yes", "org.example.attacker": "value",
		}},
		{"changed value", map[string]string{"org.example.declared": "no"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := buildCreateRequest(t, p, network, nil,
				map[string]any{"Annotations": tc.value}, nil)
			resp := doRequest(t, h.socket, "POST", "/containers/create", string(body))
			if resp.StatusCode < 300 {
				t.Fatalf("the request was accepted, but %s must be refused", tc.name)
			}
			if out := readBody(t, resp); !strings.Contains(out, "HostConfig.Annotations") {
				t.Errorf("expected the denial to name the field, got:\\n%s", out)
			}
		})
	}
}
