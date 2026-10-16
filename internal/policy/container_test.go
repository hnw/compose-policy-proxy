package policy

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

// Ownership is settled through Authorize, so these tests describe what a client
// may do to a container rather than what a helper returns.

// containerID is the identifier the stub Engine answers for. Ownership is read off
// the container the Engine reports, so the tests use one arbitrary id throughout.
const containerID = "0123456789abcdef"

func inspectFixture() (types.Project, types.ServiceConfig, container.InspectResponse) {
	project, service, create := fixture()
	project.Services = types.Services{"app": service}
	return *project, service, inspectOf(*project, service, create)
}

// inspectOf renders a create request the way the daemon reports it back. Ownership
// is read off that report, so a test must not inherit the fixture's labels.
func inspectOf(
	project types.Project,
	service types.ServiceConfig,
	create *container.CreateRequest,
) container.InspectResponse {
	hostConfig := &container.HostConfig{
		CapAdd:            create.HostConfig.CapAdd,
		CapDrop:           create.HostConfig.CapDrop,
		GroupAdd:          create.HostConfig.GroupAdd,
		Privileged:        true,
		ReadonlyRootfs:    true,
		SecurityOpt:       create.HostConfig.SecurityOpt,
		Sysctls:           create.HostConfig.Sysctls,
		NetworkMode:       "demo_frontend",
		Devices:           create.HostConfig.Devices,
		DeviceCgroupRules: create.HostConfig.DeviceCgroupRules,
		Binds:             create.HostConfig.Binds,
		Tmpfs:             create.HostConfig.Tmpfs,
		PortBindings:      create.HostConfig.PortBindings,
		CgroupParent:      create.HostConfig.CgroupParent,
		Isolation:         create.HostConfig.Isolation,
		VolumesFrom:       create.HostConfig.VolumesFrom,
		Links:             create.HostConfig.Links,
	}
	insp := container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			Name:       "/demo-" + service.Name + "-run-abc123",
			HostConfig: hostConfig,
		},
		Config: create.Config,
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"demo_frontend": {
					Aliases:     []string{"demo-" + service.Name + "-run-abc123"},
					IPAMConfig:  &network.EndpointIPAMConfig{IPv4Address: "172.30.0.10"},
					MacAddress:  "02:0a:ac:1e:00:0a", // assigned by the daemon
					GwPriority:  100,
					NetworkID:   "net-id-assigned-by-daemon",
					EndpointID:  "endpoint-id-assigned-by-daemon",
					Gateway:     "172.30.0.1",
					IPPrefixLen: 24,
				},
			},
		},
	}
	insp.Config.Labels = map[string]string{
		LabelProject: project.Name,
		LabelService: service.Name,
		LabelOneoff:  oneoffLabelValue,
	}

	// Values the daemon substitutes when the create request left them out.
	insp.HostConfig.Runtime = "runc"
	insp.HostConfig.IpcMode = "private"
	insp.HostConfig.CgroupnsMode = "host"
	insp.HostConfig.UsernsMode = "host"
	insp.HostConfig.UTSMode = "host"
	insp.HostConfig.PidMode = "host"
	insp.HostConfig.MaskedPaths = []string{"/proc/acpi", "/proc/kcore"}
	insp.HostConfig.ReadonlyPaths = []string{"/proc/bus"}
	insp.HostConfig.ConsoleSize = [2]uint{80, 24}
	insp.HostConfig.RestartPolicy = container.RestartPolicy{Name: "no"}
	insp.HostConfig.LogConfig = container.LogConfig{Type: "json-file"}

	return insp
}

// stubInspector is an Engine that knows a fixed set of containers. Any other
// identifier is unknown to it, which is what an unreadable container looks like.
type stubInspector map[string]container.InspectResponse

func (s stubInspector) InspectContainer(_ context.Context, id string) (container.InspectResponse, error) {
	insp, ok := s[id]
	if !ok {
		return container.InspectResponse{}, errors.New("no such container")
	}
	return insp, nil
}

func inspectPolicy(project *types.Project, insp container.InspectResponse) *Policy {
	return policyFor(project, insp, DefaultCommands())
}

func policyFor(project *types.Project, insp container.InspectResponse, commands Commands) *Policy {
	return &Policy{project: project, inspect: stubInspector{containerID: insp}, commands: commands}
}

// request builds the request a client sends, as the proxy receives it. A URL
// with no scheme or host of its own, because it arrived over a Unix socket.
func request(t *testing.T, method, path string) *Request {
	t.Helper()
	u, err := url.Parse("http://docker" + path)
	if err != nil {
		t.Fatalf("parse %q: %v", path, err)
	}
	return &Request{Method: method, URL: u}
}

func inspect(t *testing.T, p *Policy) (Decision, error) {
	t.Helper()
	return p.Authorize(t.Context(), request(t, "GET", "/v1.51/containers/"+containerID+"/json"))
}

func TestControlIsGrantedToOneOffContainersOnly(t *testing.T) {
	// A service container reports the label as False, or not at all.
	ordinary := func(i *container.InspectResponse) { delete(i.Config.Labels, LabelOneoff) }
	labelledFalse := func(i *container.InspectResponse) { i.Config.Labels[LabelOneoff] = "False" }

	cases := []struct {
		name    string
		method  string
		path    string
		prepare func(*container.InspectResponse)
		want    bool // allowed
	}{
		{
			name: "a one-off container", method: "POST", path: "/stop", want: true,
		},
		{
			name: "killing a service container", method: "POST", path: "/kill",
			prepare: ordinary,
		},
		{
			name: "killing a container labelled oneoff false", method: "POST", path: "/kill",
			prepare: labelledFalse,
		},
		{
			name: "removing a service container", method: "DELETE",
			prepare: labelledFalse,
		},
		{
			name: "attaching to a service container", method: "POST", path: "/attach",
			prepare: labelledFalse,
		},
		{
			name: "resizing a service container", method: "POST", path: "/resize?h=24&w=80",
			prepare: labelledFalse,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project, _, insp := inspectFixture()
			if tc.prepare != nil {
				tc.prepare(&insp)
			}
			p := inspectPolicy(&project, insp)
			_, err := p.Authorize(t.Context(), request(t, tc.method, "/v1.51/containers/"+containerID+tc.path))
			if tc.want {
				if err != nil {
					t.Fatalf("%s %s must be allowed, got %v", tc.method, tc.path, err)
				}
				return
			}
			pe, ok := Inspect(err)
			if !ok {
				t.Fatalf("%s %s was allowed, or failed without a policy refusal: %v", tc.method, tc.path, err)
			}
			if pe.Field != LabelOneoff {
				t.Fatalf("%s %s was refused on %q, want the one-off label (%s)",
					tc.method, tc.path, pe.Field, pe.Detail)
			}
		})
	}
}

func TestOwnershipAcceptsMatchingContainer(t *testing.T) {
	project, _, insp := inspectFixture()

	decision, err := inspect(t, inspectPolicy(&project, insp))
	if err != nil {
		t.Fatalf("expected the container to be recognised, got %v", err)
	}
	if decision.Service != "app" {
		t.Fatalf("expected service %q, got %q", "app", decision.Service)
	}
}

// TestOwnershipDeniesForeignProject covers a container configured exactly like the
// service but carrying another project's label. Identical state is not ownership.
func TestOwnershipDeniesForeignProject(t *testing.T) {
	project, _, insp := inspectFixture()
	insp.Config.Labels[LabelProject] = "another-project"

	_, err := inspect(t, inspectPolicy(&project, insp))
	if pe, ok := Inspect(err); !ok || pe.Field != LabelProject {
		t.Fatalf("expected the denial to name the project label, got %v", err)
	}
}

func TestOwnershipDeniesUnknownService(t *testing.T) {
	project, _, insp := inspectFixture()
	insp.Config.Labels[LabelService] = "not-in-this-project"

	_, err := inspect(t, inspectPolicy(&project, insp))
	if err == nil {
		t.Fatal("a container naming an unknown service was accepted")
	}
}

// TestOwnershipDeniesAContainerTheEngineCannotReport covers the boundary the policy
// cannot reason past. Without an inspect result there is nothing to prove ownership.
func TestOwnershipDeniesAContainerTheEngineCannotReport(t *testing.T) {
	project, _, _ := inspectFixture()
	p := &Policy{project: &project, inspect: stubInspector{}}

	_, err := inspect(t, p)
	pe, ok := Inspect(err)
	if !ok {
		t.Fatalf("expected a denial, got %v", err)
	}
	if pe.Field != "" {
		t.Errorf("a container that cannot be inspected is not a field difference, got field %q", pe.Field)
	}
	if pe.Detail == "" {
		t.Error("the refusal must explain itself")
	}
}

func TestOwnershipToleratesDaemonDefaults(t *testing.T) {
	// Each of these is a value the daemon fills in, which an inspect result
	// cannot distinguish from one the client requested.
	mutations := map[string]func(*container.InspectResponse, *types.ServiceConfig){
		"runtime": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.Runtime = "some-other-default"
		},
		"ipc namespace":    func(i *container.InspectResponse, _ *types.ServiceConfig) { i.HostConfig.IpcMode = "" },
		"cgroup namespace": func(i *container.InspectResponse, _ *types.ServiceConfig) { i.HostConfig.CgroupnsMode = "private" },
		"masked paths":     func(i *container.InspectResponse, _ *types.ServiceConfig) { i.HostConfig.MaskedPaths = nil },
		"readonly paths":   func(i *container.InspectResponse, _ *types.ServiceConfig) { i.HostConfig.ReadonlyPaths = nil },
		"assigned mac": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.NetworkSettings.Networks["demo_frontend"].MacAddress = "02:ff:ff:ff:ff:ff"
		},
		"console size": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.ConsoleSize = [2]uint{0, 0}
		},
		"restart policy": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.RestartPolicy = container.RestartPolicy{Name: "on-failure", MaximumRetryCount: 3}
		},
		"log driver": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.LogConfig = container.LogConfig{Type: "local"}
		},
		"default hostname": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			// Compose declared none, so the daemon supplied the container id.
			svc.Hostname = ""
			i.Config.Hostname = "a1b2c3d4e5f6"
		},
		"entrypoint from the image": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.Entrypoint = nil
			i.Config.Entrypoint = []string{"/ko-app/entrypoint"}
		},
		"user from the image": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.User = ""
			i.Config.User = "0:0"
		},
		"volume declared by the image": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.Config.Volumes = map[string]struct{}{"/var/lib/data": {}}
		},
		"endpoint of the pinned network mode": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.NetworkMode = "none"
			i.HostConfig.NetworkMode = "none"
			i.NetworkSettings.Networks = map[string]*network.EndpointSettings{"none": {}}
		},
		"endpoint of the host network mode": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.NetworkMode = "host"
			i.HostConfig.NetworkMode = "host"
			i.NetworkSettings.Networks = map[string]*network.EndpointSettings{"host": {}}
		},
		"default working directory": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.WorkingDir = ""
			i.Config.WorkingDir = "/"
		},
		"default init flag": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.Init = nil
			enabled := true
			i.HostConfig.Init = &enabled
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			project, service, insp := inspectFixture()
			mutate(&insp, &service)
			// Ownership resolves the service from the project, so a Compose side
			// mutation has to be written back into it.
			project.Services["app"] = service
			if _, err := inspect(t, inspectPolicy(&project, insp)); err != nil {
				t.Fatalf("the daemon default %q should be tolerated on the inspect path, got %v", name, err)
			}
		})
	}
}

func TestOwnershipStillRejectsRealDifferences(t *testing.T) {
	// The relaxations above must not weaken the actual security comparison.
	mutations := map[string]func(*container.InspectResponse, *types.ServiceConfig){
		"different user": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.Config.User = "root"
		},
		"different entrypoint": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			// Compose declares an entrypoint of its own, so the comparison applies.
			svc.Entrypoint = []string{"/entrypoint.sh"}
			i.Config.Entrypoint = []string{"/other.sh"}
		},
		"different capabilities": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.CapAdd = append(i.HostConfig.CapAdd, "CAP_SYS_ADMIN")
		},
		"dropped capability restored": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.CapDrop = nil
		},
		"writable root filesystem": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.ReadonlyRootfs = false
		},
		"extra mount": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.Binds = append(i.HostConfig.Binds, "/:/host:rw")
		},
		"network attached beside a pinned mode": func(i *container.InspectResponse, svc *types.ServiceConfig) {
			svc.NetworkMode = "none"
			i.HostConfig.NetworkMode = "none"
			i.NetworkSettings.Networks = map[string]*network.EndpointSettings{
				"none":           {},
				"demo_elsewhere": {},
			}
		},
		"different image": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.Config.Image = "alpine:latest"
		},
		"extra device": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.Devices = append(i.HostConfig.Devices, container.DeviceMapping{
				PathOnHost: "/dev/sda", PathInContainer: "/dev/sda", CgroupPermissions: "rwm",
			})
		},
		"undeclared port published": func(i *container.InspectResponse, _ *types.ServiceConfig) {
			i.HostConfig.PortBindings = map[nat.Port][]nat.PortBinding{
				"80/tcp":  {{HostPort: "8080"}},
				"443/tcp": {{HostPort: "8443"}},
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			project, service, insp := inspectFixture()
			mutate(&insp, &service)
			project.Services["app"] = service
			if _, err := inspect(t, inspectPolicy(&project, insp)); err == nil {
				t.Fatalf("the inspect path accepted a container with %s", name)
			}
		})
	}
}

// TestOwnershipStillNeedsSecurityState is the same case a client could try to
// fake. The container carries the project label and nothing else.
func TestOwnershipStillNeedsSecurityState(t *testing.T) {
	project, _, insp := inspectFixture()
	insp.HostConfig.Privileged = true
	declared := project.Services["app"]
	declared.Privileged = false
	project.Services["app"] = declared

	if _, err := inspect(t, inspectPolicy(&project, insp)); err == nil {
		t.Fatal("a container carrying the project label but more privilege was accepted")
	}
}

// TestOwnershipToleratesDaemonAddedSecurityOption covers a daemon introduced
// difference. An existing container reports "label=disable" with no SELinux label.
func TestOwnershipToleratesDaemonAddedSecurityOption(t *testing.T) {
	project, _, insp := inspectFixture()
	insp.HostConfig.SecurityOpt = []string{"no-new-privileges:true", "label=disable"}
	if _, err := inspect(t, inspectPolicy(&project, insp)); err != nil {
		t.Fatalf("a daemon-added security option should be tolerated, got %v", err)
	}
}

// TestOwnershipStillRequiresDeclaredSecurityOption is the other half. The option
// Compose asked for has to still be there.
func TestOwnershipStillRequiresDeclaredSecurityOption(t *testing.T) {
	project, _, insp := inspectFixture()
	insp.HostConfig.SecurityOpt = []string{"label=disable"}
	if _, err := inspect(t, inspectPolicy(&project, insp)); err == nil {
		t.Fatal("a container missing the declared security option was accepted")
	}
}

// TestOwnershipToleratesDaemonMACField covers the daemon repopulating the
// deprecated container-wide MAC field on inspect.
func TestOwnershipToleratesDaemonMACField(t *testing.T) {
	project, _, insp := inspectFixture()
	insp.Config.MacAddress = "02:42:ac:1e:00:0a" //nolint:staticcheck // the deprecated field is the subject of the test
	if _, err := inspect(t, inspectPolicy(&project, insp)); err != nil {
		t.Fatalf("the daemon's container-wide MAC field should be tolerated, got %v", err)
	}
}
