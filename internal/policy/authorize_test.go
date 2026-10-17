package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

// These tests use only what the proxy uses, a Policy built by New and Authorize, to
// pin the surface those two present without reaching into the package.

const (
	dockerSocket = "/var/run/docker.sock"
	listenSocket = "/run/compose-policy-proxy/docker.sock"
)

func demoProject() *types.Project {
	return &types.Project{
		Name:       "demo",
		WorkingDir: "/opt/app",
		Networks:   types.Networks{"frontend": {Name: "demo_frontend"}},
		Volumes:    types.Volumes{"cache": {Name: "demo_cache"}},
		Services: types.Services{
			"app":  {Name: "app", Image: "alpine:3.20", Networks: map[string]*types.ServiceNetworkConfig{"frontend": {}}},
			"tool": {Name: "tool", Image: "ghcr.io/hnw/compose-policy-proxy:latest"},
		},
	}
}

// inspectStub is an Engine that knows one container and one network, so that ownership
// can be tested without a daemon.
type inspectStub struct {
	containers map[string]container.InspectResponse
	networks   map[string]network.Inspect
}

func (s inspectStub) InspectContainer(_ context.Context, id string) (container.InspectResponse, error) {
	insp, ok := s.containers[id]
	if !ok {
		return container.InspectResponse{}, errors.New("no such container")
	}
	return insp, nil
}

func (s inspectStub) InspectNetwork(_ context.Context, id string) (network.Inspect, error) {
	insp, ok := s.networks[id]
	if !ok {
		return network.Inspect{}, errors.New("no such network")
	}
	return insp, nil
}

func (s inspectStub) InspectExec(_ context.Context, _ string) (policy.ExecInfo, error) {
	return policy.ExecInfo{}, errors.New("no such exec instance")
}

// appContainer is the Engine's report of the container `docker compose run app`
// would have created.
func appContainer() container.InspectResponse {
	return container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			HostConfig: &container.HostConfig{NetworkMode: "demo_frontend"},
		},
		Config: &container.Config{
			Image: "alpine:3.20",
			Labels: map[string]string{
				policy.LabelProject: "demo",
				policy.LabelService: "app",
				policy.LabelOneoff:  "True",
			},
		},
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{"demo_frontend": {}},
		},
	}
}

const networkID = "ec1b59c1122ff53ec6f9fd68b9edc0c0ade6fd111a29627e9fc558224cd2ef97"

func ownedNetwork(name, key string) network.Inspect {
	return network.Inspect{
		Name:   name,
		ID:     networkID,
		Labels: map[string]string{policy.LabelProject: "demo", policy.LabelNetwork: key},
	}
}

func appServiceContainer() container.InspectResponse {
	insp := appContainer()
	insp.Config.Labels[policy.LabelOneoff] = "False"
	return insp
}

func demoPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.New(policy.Config{
		Project:    demoProject(),
		DockerHost: dockerSocket,
		Listen:     listenSocket,
		Engine: inspectStub{
			containers: map[string]container.InspectResponse{
				"abc": appContainer(), "svc": appServiceContainer(),
			},
			networks: map[string]network.Inspect{networkID: ownedNetwork("demo_frontend", "frontend")},
		},
		AllowedCommands: policy.DefaultCommands(),
	})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	return p
}

// authorize sends one request, with its query still in the path, and reports
// what came back.
func authorize(t *testing.T, p *policy.Policy, method, path, body string) (policy.Decision, error) {
	t.Helper()
	u, err := url.Parse("http://docker" + path)
	if err != nil {
		t.Fatalf("parse %q: %v", path, err)
	}
	return p.Authorize(t.Context(), &policy.Request{Method: method, URL: u, Body: []byte(body)})
}

func TestAuthorizedRequestsReachTheDecision(t *testing.T) {
	p := demoPolicy(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"ping", "GET", "/_ping", ""},
		{"version", "GET", "/v1.51/version", ""},
		{"create", "POST", "/v1.51/containers/create", `{
			"Image":"alpine:3.20",
			"Labels":{"com.docker.compose.project":"demo","com.docker.compose.service":"app","com.docker.compose.oneoff":"True"},
			"HostConfig":{"NetworkMode":"demo_frontend"},
			"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`},
		{"service container create", "POST", "/v1.51/containers/create", `{
			"Image":"alpine:3.20",
			"Labels":{"com.docker.compose.project":"demo","com.docker.compose.service":"app","com.docker.compose.oneoff":"False"},
			"HostConfig":{"NetworkMode":"demo_frontend"},
			"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`},
		{"service container stop", "POST", "/v1.51/containers/svc/stop", ""},
		{"service container removal", "DELETE", "/v1.51/containers/svc?force=1", ""},
		{"service container rename", "POST", "/v1.51/containers/svc/rename?name=demo-app-1", ""},
		{"container inspect", "GET", "/v1.51/containers/abc/json", ""},
		{"container resize", "POST", "/v1.51/containers/abc/resize?h=24&w=80", ""},
		{"container list", "GET", "/v1.51/containers/json?filters=" +
			url.QueryEscape(`{"label":{"com.docker.compose.project=demo":true}}`), ""},
		{"image inspect", "GET", "/v1.51/images/alpine:3.20/json", ""},
		{"image inspect from a registry", "GET", "/v1.51/images/ghcr.io/hnw/compose-policy-proxy:latest/json", ""},
		{"image pull", "POST", "/v1.51/images/create?fromImage=alpine:3.20", ""},
		{"network create", "POST", "/v1.51/networks/create", `{
			"Name":"demo_frontend",
			"Labels":{"com.docker.compose.project":"demo","com.docker.compose.network":"frontend"}}`},
		{"network inspect", "GET", "/v1.51/networks/demo_frontend", ""},
		{"network inspect by the id the engine assigned", "GET", "/v1.51/networks/" + networkID, ""},
		{"network removal", "DELETE", "/v1.51/networks/" + networkID, ""},
		{"volume create", "POST", "/v1.51/volumes/create", `{
			"Name":"demo_cache",
			"Labels":{"com.docker.compose.project":"demo","com.docker.compose.volume":"cache"}}`},
		{"volume inspect", "GET", "/v1.51/volumes/demo_cache", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := authorize(t, p, tc.method, tc.path, tc.body)
			if err != nil {
				t.Fatalf("%s %s was refused: %v", tc.method, tc.path, err)
			}
			if decision.Endpoint == "" {
				t.Errorf("an authorized request must name the endpoint it matched, got %+v", decision)
			}
		})
	}
}

func TestAuthorizedRequestReportsWhatItMatched(t *testing.T) {
	p := demoPolicy(t)

	decision, err := authorize(t, p, "GET", "/v1.51/containers/abc/json", "")
	if err != nil {
		t.Fatalf("inspecting an owned container was refused: %v", err)
	}
	if decision.Endpoint != "/containers/{id}/json" {
		t.Errorf("endpoint = %q, want %q", decision.Endpoint, "/containers/{id}/json")
	}
	if decision.Target != "abc" {
		t.Errorf("target = %q, want abc", decision.Target)
	}
	if decision.Service != "app" {
		t.Errorf("service = %q, want app", decision.Service)
	}
}

func TestRefusedRequests(t *testing.T) {
	p := demoPolicy(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		// field is the Docker field the refusal must name. A refusal naming no
		// field says so with an empty one, and the detail fragment identifies it.
		field  string
		detail string
	}{
		{
			name: "a create request carrying no Compose labels", method: "POST",
			path: "/v1.51/containers/create",
			body: `{"Image":"alpine:3.20","HostConfig":{"NetworkMode":"demo_frontend"},
				"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`,
			field:  "com.docker.compose.project",
			detail: `this proxy serves project "demo"`,
		},
		{
			name: "a create request that names no kind of container", method: "POST",
			path: "/v1.51/containers/create",
			body: `{"Image":"alpine:3.20","Labels":{"com.docker.compose.project":"demo",` +
				`"com.docker.compose.service":"app"},"HostConfig":{"NetworkMode":"demo_frontend"},
				"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`,
			field:  "com.docker.compose.oneoff",
			detail: `container creation is limited to one-off containers (run) and service containers (up)`,
		},
		{
			name: "a field the compose file does not declare", method: "POST",
			path: "/v1.51/containers/create",
			body: `{"Image":"alpine:latest","Labels":{"com.docker.compose.project":"demo",` +
				`"com.docker.compose.service":"app","com.docker.compose.oneoff":"True"},
				"HostConfig":{"NetworkMode":"demo_frontend"},
				"NetworkingConfig":{"EndpointsConfig":{"demo_frontend":{}}}}`,
			field:  "Config.Image",
			detail: `compose declares "alpine:3.20", found "alpine:latest"`,
		},
		{
			name: "a create request that carries no config", method: "POST",
			path:  "/v1.51/containers/create",
			body:  `{"HostConfig":{"NetworkMode":"demo_frontend"}}`,
			field: "request",
		},
		{
			name: "a container of another project", method: "GET", path: "/v1.51/containers/other/json",
			detail: `container is not accessible through this proxy`,
		},
		{
			name: "an image the project does not declare", method: "GET", path: "/v1.51/images/busybox/json",
			detail: `image "busybox" is not declared by compose project`,
		},
		{
			name: "a pull of an undeclared image", method: "POST", path: "/v1.51/images/create?fromImage=busybox",
			field: "fromImage",
		},
		{
			name: "a pull of every image", method: "POST", path: "/v1.51/images/create?fromImage=alpine:3.20&all=1",
			field: "all",
		},
		{
			name: "a pull parameter that is not a boolean", method: "POST",
			path:  "/v1.51/images/create?fromImage=alpine:3.20&all=sometimes",
			field: "all",
		},
		{
			name: "a pull of an image out of another container", method: "POST",
			path:  "/v1.51/images/create?fromImage=alpine:3.20&fromSrc=someone_elses",
			field: "fromSrc",
		},
		{
			name: "a network the project does not declare", method: "GET", path: "/v1.51/networks/someone_elses",
			detail: `network "someone_elses" is not declared by compose project`,
		},
		{
			name: "a volume the project does not declare", method: "GET", path: "/v1.51/volumes/someone_elses",
			detail: `volume "someone_elses" is not declared by compose project`,
		},
		{
			name: "removing a volume of the project", method: "DELETE", path: "/v1.51/volumes/demo_cache",
			detail: "method DELETE is not allowed",
		},
		{
			name: "removing an image of the project", method: "DELETE", path: "/v1.51/images/alpine:3.20",
			detail: `endpoint "/images/alpine:3.20" is not allowed`,
		},
		{
			name: "a list that cannot be scoped to the project", method: "GET", path: "/v1.51/containers/json",
			detail: "list request carries no filters, so it would observe every container",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authorize(t, p, tc.method, tc.path, tc.body)
			pe, ok := policy.Inspect(err)
			if !ok {
				t.Fatalf("%s %s was allowed, or failed without a policy refusal: %v", tc.method, tc.path, err)
			}
			if pe.Field != tc.field {
				t.Fatalf("field = %q, want %q (%s)", pe.Field, tc.field, pe.Detail)
			}
			if pe.Detail == "" {
				t.Fatal("a refusal must explain itself")
			}
			if tc.detail != "" && !strings.Contains(pe.Detail, tc.detail) {
				t.Fatalf("detail = %q, want it to mention %q", pe.Detail, tc.detail)
			}
		})
	}
}

// TestOwnershipCannotBeFakedWithClientControlledLabels covers the bypass the
// protected rule needs not to exist. A client cannot reach a container by labelling it.
func TestOwnershipCannotBeFakedWithClientControlledLabels(t *testing.T) {
	project := demoProject()
	containerOf := appContainer()
	containerOf.Config.Labels[policy.LabelProject] = "someone-elses-project"
	stub := inspectStub{containers: map[string]container.InspectResponse{"abc": containerOf}}
	p, err := policy.New(policy.Config{
		Project:    project,
		DockerHost: dockerSocket,
		Listen:     listenSocket,
		Engine:     stub,
		// Every command is allowed, so a refusal below can only come from ownership.
		AllowedCommands: policy.DefaultCommands(),
	})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	for _, op := range []struct{ method, path string }{
		{http.MethodGet, "/v1.51/containers/abc/json"},
		{http.MethodGet, "/v1.51/containers/abc/logs?stdout=1"},
		{http.MethodPost, "/v1.51/containers/abc/stop"},
		{http.MethodPost, "/v1.51/containers/abc/restart"},
		{http.MethodPost, "/v1.51/containers/abc/attach"},
		{http.MethodPost, "/v1.51/containers/abc/resize?h=24&w=80"},
		{http.MethodDelete, "/v1.51/containers/abc"},
	} {
		if _, err := authorize(t, p, op.method, op.path, ""); err == nil {
			t.Errorf("%s %s reached a container of another project", op.method, op.path)
		}
	}
}

// A seccomp profile as Compose declares it on disk, and the compacted form the
// daemon receives instead.
const (
	seccompFile = `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [{"names": ["read"], "action": "SCMP_ACT_ALLOW"}]
}`
	seccompJSON = `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read"],"action":"SCMP_ACT_ALLOW"}]}`
)

// seccompDir writes a profile into a fresh directory the project resolves
// against. An empty content leaves the file absent.
func seccompDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if content == "" {
		return dir
	}
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(content), 0o600); err != nil {
		t.Fatalf("write seccomp profile: %v", err)
	}
	return dir
}

// seccompProject declares a service "app" whose security_opt names a seccomp
// profile file in dir, either active or disabled by a profile.
func seccompProject(dir string, disabled bool) *types.Project {
	project := demoProject()
	project.WorkingDir = dir
	app := types.ServiceConfig{
		Name:        "app",
		Image:       "alpine:3.20",
		Networks:    map[string]*types.ServiceNetworkConfig{"frontend": {}},
		SecurityOpt: []string{"seccomp=./profile.json"},
	}
	if disabled {
		delete(project.Services, "app")
		project.DisabledServices = types.Services{"app": app}
		return project
	}
	project.Services["app"] = app
	return project
}

func seccompPolicy(project *types.Project) (*policy.Policy, error) {
	return policy.New(policy.Config{
		Project:         project,
		DockerHost:      dockerSocket,
		Listen:          listenSocket,
		Engine:          inspectStub{},
		AllowedCommands: policy.DefaultCommands(),
	})
}

func seccompCreateBody(t *testing.T, profile string) []byte {
	t.Helper()
	body, err := json.Marshal(container.CreateRequest{
		Config: &container.Config{
			Image:  "alpine:3.20",
			Labels: map[string]string{policy.LabelProject: "demo", policy.LabelService: "app", policy.LabelOneoff: "True"},
		},
		HostConfig: &container.HostConfig{
			NetworkMode: "demo_frontend",
			SecurityOpt: []string{"seccomp=" + profile},
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{"demo_frontend": {}},
		},
	})
	if err != nil {
		t.Fatalf("encode create request: %v", err)
	}
	return body
}

func TestSeccompProfileIsResolvedAtStartup(t *testing.T) {
	dir := seccompDir(t, seccompFile)
	p, err := seccompPolicy(seccompProject(dir, false))
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	// The profile is gone before any request arrives, since a decision may not
	// depend on what the file system holds at that point.
	if err := os.Remove(filepath.Join(dir, "profile.json")); err != nil {
		t.Fatalf("remove seccomp profile: %v", err)
	}

	decision, err := authorize(t, p, http.MethodPost, "/v1.51/containers/create",
		string(seccompCreateBody(t, seccompJSON)))
	if err != nil {
		t.Fatalf("the profile read at startup was refused: %v", err)
	}
	if decision.Service != "app" {
		t.Fatalf("service = %q, want app", decision.Service)
	}

	// The comparison is still against what the project declared at startup, so
	// a profile of the request's own choosing is not accepted in its place.
	if _, err := authorize(t, p, http.MethodPost, "/v1.51/containers/create",
		string(seccompCreateBody(t, `{"defaultAction":"SCMP_ACT_ALLOW"}`))); err == nil {
		t.Fatal("a request carrying a different seccomp profile was accepted")
	}
}

// A service a profile disables is still one the proxy describes, so its profile
// is resolved at startup like an active service's.
func TestSeccompProfileOfADisabledServiceIsResolvedAtStartup(t *testing.T) {
	p, err := seccompPolicy(seccompProject(seccompDir(t, seccompFile), true))
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}
	decision, err := authorize(t, p, http.MethodPost, "/v1.51/containers/create",
		string(seccompCreateBody(t, seccompJSON)))
	if err != nil {
		t.Fatalf("the profile of a profile-disabled service was refused: %v", err)
	}
	if decision.Service != "app" {
		t.Fatalf("service = %q, want app", decision.Service)
	}
}

func TestPolicyDoesNotStartOnAnUnusableSeccompProfile(t *testing.T) {
	cases := []struct {
		name     string
		disabled bool
		content  string // empty leaves the profile file absent
	}{
		{"a missing profile of an active service", false, ""},
		{"a profile of an active service that is not JSON", false, "{ not json"},
		{"a missing profile of a disabled service", true, ""},
		{"a profile of a disabled service that is not JSON", true, "{ not json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := seccompPolicy(seccompProject(seccompDir(t, tc.content), tc.disabled)); err == nil {
				t.Fatal("a policy was built from a seccomp profile it cannot use")
			}
		})
	}
}
