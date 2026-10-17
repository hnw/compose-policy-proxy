package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
)

// The protected-service rule is applied from Authorize, so that these tests
// describe what a client can and cannot do rather than which helper refused.

// A protected deployment has three services. The proxy holds the Engine socket, an
// application holds only the proxy's restricted socket, and an ordinary one holds neither.
const (
	hostSocket  = "/var/run/docker.sock"
	proxySocket = "/run/compose-policy-proxy/docker.sock"
)

// socketService turns the shared fixture into a service that mounts source at
// the Docker socket path, together with the create request that matches it.
func socketService(
	base types.ServiceConfig,
	req *container.CreateRequest,
	name, source string,
) (types.ServiceConfig, *container.CreateRequest) {
	service := base
	service.Name = name
	service.Volumes = []types.ServiceVolumeConfig{{
		Type: types.VolumeTypeBind,
		// Short-syntax binds create the mountpoint, which is what a Compose client
		// sends for this form.
		Bind:   &types.ServiceVolumeBind{CreateHostPath: true},
		Source: source,
		Target: hostSocket,
	}}
	service.Tmpfs = nil

	req.Config.Labels = map[string]string{
		LabelProject: projectName,
		LabelService: name,
		LabelOneoff:  oneoffLabelValue,
	}
	req.HostConfig.Binds = []string{source + ":" + hostSocket}
	req.HostConfig.Tmpfs = nil
	return service, req
}

// protectedFixture adds a proxy service, an application using the restricted socket and
// an ordinary one. New resolves the protected set, so the detection rule is covered too.
func protectedFixture() (*Policy, map[string]*container.CreateRequest, stubInspector) {
	project := &types.Project{
		Name:       projectName,
		WorkingDir: projectDir,
		Networks:   types.Networks{"frontend": {Name: "demo_frontend"}},
		Volumes:    types.Volumes{"cache": {Name: "demo_cache"}},
	}
	project.Services = types.Services{}
	requests := map[string]*container.CreateRequest{}
	inspector := stubInspector{containers: map[string]container.InspectResponse{}}

	for _, spec := range []struct{ name, source string }{
		{"proxy", hostSocket},
		{"runner", proxySocket},
	} {
		_, service, req := fixture()
		service, req = socketService(service, req, spec.name, spec.source)
		project.Services[spec.name] = service
		requests[spec.name] = req
		inspector.containers[spec.name] = inspectOf(*project, service, req)
	}

	_, service, req := fixture()
	req.Config.Labels = map[string]string{
		LabelProject: projectName,
		LabelService: service.Name,
		LabelOneoff:  oneoffLabelValue,
	}
	project.Services[service.Name] = service
	requests[service.Name] = req
	inspector.containers[service.Name] = inspectOf(*project, service, req)

	p, err := New(Config{
		Project:         project,
		DockerHost:      hostSocket,
		Listen:          proxySocket,
		Engine:          inspector,
		AllowedCommands: DefaultCommands(),
	})
	if err != nil {
		panic(err)
	}
	return p, requests, inspector
}

// create runs the container create request a client would send for a service.
func create(t *testing.T, p *Policy, req *container.CreateRequest) (Decision, error) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("encode create request: %v", err)
	}
	r := request(t, "POST", "/v1.51/containers/create")
	r.Body = body
	return p.Authorize(t.Context(), r)
}

// TestProtectedServicesAreResolvedFromTheProject pins what the set is before any
// request. Only the service holding the upstream socket belongs to it.
func TestProtectedServicesAreResolvedFromTheProject(t *testing.T) {
	p, _, _ := protectedFixture()

	names := p.ProtectedServices()
	if len(names) != 1 || names[0] != "proxy" {
		t.Fatalf("protected services = %v, want [proxy]", names)
	}
}

func TestProtectedServiceCannotBeCreated(t *testing.T) {
	p, requests, _ := protectedFixture()

	_, err := create(t, p, requests["proxy"])
	pe, ok := Inspect(err)
	if !ok {
		t.Fatalf("expected a policy denial, got %v", err)
	}
	if pe.Service != "proxy" {
		t.Errorf("the denial should name the service, got %q", pe.Service)
	}
	if pe.Field != "" {
		t.Errorf("a protected service is refused as a whole, not over a field, got %q", pe.Field)
	}
	if !strings.Contains(pe.Detail, "not allowed for a protected service") {
		t.Errorf("the denial must name the classification, got %q", pe.Detail)
	}
	if strings.Contains(pe.Detail, "Docker socket") {
		t.Errorf("the denial must not explain how the service is classified, got %q", pe.Detail)
	}
	if want := `service "proxy": `; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("refusal = %q, want it to open with %q", err, want)
	}
}

func TestProtectedServiceContainerCannotBeCreated(t *testing.T) {
	p, requests, _ := protectedFixture()

	req := requests["proxy"]
	req.Config.Labels[LabelOneoff] = serviceLabelValue
	_, err := create(t, p, req)
	pe, ok := Inspect(err)
	if !ok {
		t.Fatalf("a service container of a protected service was accepted: %v", err)
	}
	if pe.Service != "proxy" || !strings.Contains(pe.Detail, "not allowed for a protected service") {
		t.Errorf("denial = %v, want the protected-service one", err)
	}
}

func TestUnprotectedServiceContainerCanBeCreated(t *testing.T) {
	p, requests, _ := protectedFixture()

	req := requests["app"]
	req.Config.Labels[LabelOneoff] = serviceLabelValue
	decision, err := create(t, p, req)
	if err != nil {
		t.Fatalf("the container of an unprotected service must remain launchable, got %v", err)
	}
	if decision.Service != "app" {
		t.Fatalf("matched %q, want app", decision.Service)
	}
}

func TestUnprotectedOneOffCanBeCreated(t *testing.T) {
	p, requests, _ := protectedFixture()

	decision, err := create(t, p, requests["app"])
	if err != nil {
		t.Fatalf("a one-off container of an unprotected service must remain launchable, got %v", err)
	}
	if decision.Service != "app" {
		t.Fatalf("matched %q, want app", decision.Service)
	}
}

func TestServiceUsingTheRestrictedSocketCanBeCreated(t *testing.T) {
	// This is the deployment the proxy is built for. The container holds the
	// proxy's socket at the Docker socket path and reaches the Engine only through it.
	p, requests, _ := protectedFixture()

	decision, err := create(t, p, requests["runner"])
	if err != nil {
		t.Fatalf("a service using the restricted socket must remain launchable, got %v", err)
	}
	if decision.Service != "runner" {
		t.Fatalf("matched %q, want runner", decision.Service)
	}
}

func TestProtectedServiceFieldMismatchIsStillReportedAsSuch(t *testing.T) {
	// The refusal names the field that differs, so that it says what is wrong
	// rather than only which service was addressed.
	p, requests, _ := protectedFixture()

	req := requests["proxy"]
	req.Config.User = "0:0"
	_, err := create(t, p, req)
	pe, ok := Inspect(err)
	if !ok {
		t.Fatalf("expected a policy denial, got %v", err)
	}
	if pe.Field != "Config.User" {
		t.Fatalf("field = %q, want Config.User (%s)", pe.Field, pe.Detail)
	}
}

// The stub Engine is keyed by service name, so "containers/proxy" addresses the
// protected container. The identifier is arbitrary, ownership comes from the report.
// Every command is allowed, so each refusal below is the protected rule rather than the
// missing command.
func TestProtectedContainerOperations(t *testing.T) {
	p, _, _ := protectedFixture()

	cases := []struct {
		operation string
		method    string
		path      string
		want      bool // allowed
	}{
		{"inspect", "GET", "/json", true},
		{"read", "GET", "", true},
		{"wait", "POST", "/wait", true},
		{"start", "POST", "/start", false},
		{"stop", "POST", "/stop", false},
		{"rename", "POST", "/rename?name=demo-proxy-1", false},
		{"restart", "POST", "/restart", false},
		{"logs", "GET", "/logs", false},
		{"kill", "POST", "/kill", false},
		{"remove", "DELETE", "", false},
		{"attach", "POST", "/attach", false},
		{"resize", "POST", "/resize", false},
	}
	for _, tc := range cases {
		t.Run(tc.operation, func(t *testing.T) {
			decision, err := p.Authorize(t.Context(), request(t, tc.method, "/v1.51/containers/proxy"+tc.path))
			if tc.want {
				if err != nil {
					t.Fatalf("%s must remain available on a protected container, got %v", tc.operation, err)
				}
				if decision.Service != "proxy" {
					t.Fatalf("resolved service %q, want proxy", decision.Service)
				}
				return
			}
			pe, ok := Inspect(err)
			if !ok {
				t.Fatalf("%s must be denied, got %v", tc.operation, err)
			}
			if pe.Service != "proxy" {
				t.Fatalf("denial named service %q, want the protected one", pe.Service)
			}
			if pe.Field != "" {
				t.Fatalf("denial named field %q, want none", pe.Field)
			}
		})
	}
}

func TestUnprotectedOneOffKeepsAllowedOperations(t *testing.T) {
	p, _, _ := protectedFixture()

	for _, op := range []struct{ method, suffix string }{
		{"GET", "/json"},
		{"POST", "/stop"},
		{"POST", "/start"},
		{"POST", "/kill"},
		{"POST", "/resize?h=24&w=80"},
		{"DELETE", ""},
	} {
		t.Run(op.method+op.suffix, func(t *testing.T) {
			decision, err := p.Authorize(t.Context(), request(t, op.method, "/v1.51/containers/app"+op.suffix))
			if err != nil {
				t.Fatalf("a one-off container of an unprotected service must keep %s %s, got %v", op.method, op.suffix, err)
			}
			if decision.Service != "app" {
				t.Fatalf("resolved service %q, want app", decision.Service)
			}
		})
	}
}
