package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
)

// An exec id names no container, so every operation on one is decided from what the
// Engine reports about it and about the container it belongs to.

const (
	execID            = "an-exec"
	terminalExecID    = "an-exec-with-a-terminal"
	privilegedExecID  = "an-exec-the-engine-holds-with-privilege"
	userExecID        = "an-exec-the-engine-holds-for-another-user"
	unreportedExecID  = "an-exec-the-engine-reports-nothing-for"
	foreignExecID     = "an-exec-of-a-container-elsewhere"
	protectedExecID   = "an-exec-of-the-protected-container"
	unprotectedExecID = "an-exec-of-the-restricted-socket-holder"
	unknownExecID     = "an-exec-the-engine-does-not-know"
	unsetExecID       = "an-exec-the-engine-reports-no-privilege-for"

	// serviceID is the ordinary service container of the project, as opposed to the
	// one-off the shared fixture describes.
	serviceID = "0123456789abcdeff"
)

// The Engine reports the privilege of every exec it holds, so an answer without it is
// a field the policy must refuse rather than read as unprivileged.
var (
	privileged   = true
	unprivileged = false
)

// execInspector is an Engine that knows the fixture's containers and a fixed set of
// exec instances running in them.
type execInspector struct {
	stubInspector
	execs map[string]ExecInfo
}

func (e execInspector) InspectExec(_ context.Context, id string) (ExecInfo, error) {
	info, ok := e.execs[id]
	if !ok {
		return ExecInfo{}, errors.New("no such exec instance")
	}
	return info, nil
}

// execFixture is a project with an owned one-off container, an owned service container,
// and execs in them. The service declares no user, so an exec created without one runs
// as the container does.
func execFixture(commands Commands) *Policy {
	project, service, oneOff := inspectFixture()
	service.User = ""
	service.Privileged = false
	project.Services["app"] = service
	oneOff.Config.User = ""
	oneOff.HostConfig.Privileged = false

	ordinary := oneOff
	config := *oneOff.Config
	config.Labels = make(map[string]string, len(oneOff.Config.Labels))
	for name, value := range oneOff.Config.Labels {
		config.Labels[name] = value
	}
	delete(config.Labels, LabelOneoff)
	ordinary.Config = &config

	return &Policy{
		project: &project,
		inspect: execInspector{
			stubInspector: stubInspector{containers: map[string]container.InspectResponse{
				containerID: oneOff, serviceID: ordinary,
			}},
			execs: map[string]ExecInfo{
				execID:         {ContainerID: containerID, ProcessConfig: &ExecProcessConfig{Privileged: &unprivileged}},
				terminalExecID: {ContainerID: containerID, ProcessConfig: &ExecProcessConfig{Privileged: &unprivileged, Tty: true}},
				// An exec the Engine holds with more privilege than the proxy would
				// create, one it holds for a user of its own, and one whose answer
				// omits the privilege the proxy judges on.
				privilegedExecID: {ContainerID: containerID, ProcessConfig: &ExecProcessConfig{Privileged: &privileged}},
				userExecID: {ContainerID: containerID, ProcessConfig: &ExecProcessConfig{
					Privileged: &unprivileged, User: "1000:1000"}},
				unsetExecID:      {ContainerID: containerID, ProcessConfig: &ExecProcessConfig{}},
				unreportedExecID: {ContainerID: containerID},
				foreignExecID: {ContainerID: "a-container-elsewhere",
					ProcessConfig: &ExecProcessConfig{Privileged: &unprivileged}},
			},
		},
		commands: commands,
	}
}

func authorize(t *testing.T, p *Policy, method, path, body string) (Decision, error) {
	t.Helper()
	req := request(t, method, path)
	req.Body = []byte(body)
	return p.Authorize(t.Context(), req)
}

// TestExecOperationsAreGrantedToOwnedContainers is the whole of what
// `docker compose exec` performs: create an exec, start it, and read its exit status
// back, with the resize a terminal sends beside it.
func TestExecOperationsAreGrantedToOwnedContainers(t *testing.T) {
	p := execFixture(DefaultCommands())

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name: "create in a one-off container", method: "POST",
			path: "/v1.51/containers/" + containerID + "/exec",
			body: `{"Cmd":["sh","-c","true"],"AttachStdout":true,"DetachKeys":"ctrl-p,ctrl-q"}`,
		},
		{
			name: "create in a service container", method: "POST",
			path: "/v1.51/containers/" + serviceID + "/exec",
			body: `{"Cmd":["true"],"Env":["A=1"],"WorkingDir":"/app","Tty":true}`,
		},
		{
			name: "start", method: "POST",
			path: "/v1.51/exec/" + execID + "/start", body: `{"Detach":false,"Tty":false}`,
		},
		{
			name: "start with the terminal it was created with", method: "POST",
			path: "/v1.51/exec/" + terminalExecID + "/start",
			body: `{"Detach":false,"Tty":true,"ConsoleSize":[0,0]}`,
		},
		{
			name: "read the exit status", method: "GET",
			path: "/v1.51/exec/" + execID + "/json",
		},
		{
			name: "resize", method: "POST",
			path: "/v1.51/exec/" + terminalExecID + "/resize?h=24&w=80",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := authorize(t, p, tc.method, tc.path, tc.body)
			if err != nil {
				t.Fatalf("%s %s must be allowed, got %v", tc.method, tc.path, err)
			}
			if decision.Service != "app" {
				t.Errorf("resolved service %q, want app", decision.Service)
			}
		})
	}

	// Reading an exec observes rather than acts, so it needs no command of its own.
	if _, err := authorize(t, execFixture(nil), "GET", "/v1.51/exec/"+execID+"/json", ""); err != nil {
		t.Errorf("reading an exec must not need a command, got %v", err)
	}
}

func TestRefusedExecs(t *testing.T) {
	p := execFixture(DefaultCommands())

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   string
		// field is the Docker field the refusal must name, and detail a fragment of
		// the explanation.
		field  string
		detail string
	}{
		{
			name: "a privileged exec", method: "POST",
			path:  "/v1.51/containers/" + containerID + "/exec",
			body:  `{"Cmd":["true"],"Privileged":true}`,
			field: "Privileged", detail: "may not be privileged",
		},
		{
			name: "an exec naming a user", method: "POST",
			path:  "/v1.51/containers/" + containerID + "/exec",
			body:  `{"Cmd":["true"],"User":"root"}`,
			field: "User", detail: "may not run as a user",
		},
		{
			name: "an exec for a container the project does not own", method: "POST",
			path: "/v1.51/containers/someone-elses/exec", body: `{"Cmd":["true"]}`,
			detail: "container is not accessible through this proxy",
		},
		{
			name: "starting an exec the Engine holds with privilege", method: "POST",
			path:  "/v1.51/exec/" + privilegedExecID + "/start",
			body:  `{"Detach":true,"Tty":false}`,
			field: "Privileged", detail: "may not be privileged",
		},
		{
			name: "resizing an exec the Engine holds for another user", method: "POST",
			path:  "/v1.51/exec/" + userExecID + "/resize?h=24&w=80",
			field: "User", detail: "an exec may not run as a user other than the container's",
		},
		{
			name: "starting an exec the Engine reports no privilege for", method: "POST",
			path:   "/v1.51/exec/" + unreportedExecID + "/start",
			body:   `{"Detach":true,"Tty":false}`,
			detail: "no process configuration",
		},
		{
			name: "starting an exec of a container the project does not own", method: "POST",
			path: "/v1.51/exec/" + foreignExecID + "/start", body: `{"Detach":true,"Tty":false}`,
			detail: "container is not accessible through this proxy",
		},
		{
			name: "an exec id the Engine does not know", method: "POST",
			path: "/v1.51/exec/" + unknownExecID + "/start", body: `{"Detach":true,"Tty":false}`,
			detail: "the exec instance cannot be read through this proxy",
		},
		{
			name: "starting an exec with a terminal it was not created with", method: "POST",
			path: "/v1.51/exec/" + execID + "/start", body: `{"Detach":false,"Tty":true}`,
			field: "Tty", detail: "the terminal it was created with",
		},
		{
			name: "an exec create body that does not decode", method: "POST",
			path: "/v1.51/containers/" + containerID + "/exec", body: `{"Cmd":["true"],"SomeNewField":1}`,
			detail: "exec create request cannot be decoded",
		},
		{
			name: "an exec start body that does not decode", method: "POST",
			path: "/v1.51/exec/" + execID + "/start", body: `{"Detached":true}`,
			detail: "exec start request cannot be decoded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := authorize(t, p, tc.method, tc.path, tc.body)
			pe, ok := Inspect(err)
			if !ok {
				t.Fatalf("%s %s was allowed, or failed without a policy refusal: %v",
					tc.method, tc.path, err)
			}
			if pe.Field != tc.field {
				t.Fatalf("field = %q, want %q (%s)", pe.Field, tc.field, pe.Detail)
			}
			if !strings.Contains(pe.Detail, tc.detail) {
				t.Fatalf("detail = %q, want it to mention %q", pe.Detail, tc.detail)
			}
		})
	}
}

// TestExecFollowsItsOwnCommand pins that `exec` is a permission of its own, like
// `start` and `stop`: authorizing one-off containers says nothing about running a
// command inside one that already exists.
func TestExecFollowsItsOwnCommand(t *testing.T) {
	for _, tc := range []struct {
		name     string
		commands Commands
		want     bool // allowed
	}{
		{"omitted", DefaultCommands(), true},
		{"exec", Commands{commandExec}, true},
		{"run", Commands{commandRun}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := execFixture(tc.commands)
			for _, op := range []struct{ method, path, body string }{
				{"POST", "/v1.51/containers/" + containerID + "/exec", `{"Cmd":["true"]}`},
				{"POST", "/v1.51/exec/" + execID + "/start", `{"Detach":false,"Tty":false}`},
				{"POST", "/v1.51/exec/" + execID + "/resize?h=24&w=80", ""},
			} {
				_, err := authorize(t, p, op.method, op.path, op.body)
				if tc.want != (err == nil) {
					t.Fatalf("%s %s with %v: err = %v, want allowed = %t",
						op.method, op.path, tc.commands, err, tc.want)
				}
				if tc.want {
					continue
				}
				pe, ok := Inspect(err)
				if !ok {
					t.Fatalf("%s %s was refused for something other than the policy: %v",
						op.method, op.path, err)
				}
				if want := "compose exec is not available"; !strings.Contains(pe.Detail, want) {
					t.Errorf("%s %s was refused as %q, want a refusal naming %q",
						op.method, op.path, pe.Detail, want)
				}
			}
		})
	}
}

// TestProtectedServiceCannotBeExecutedIn covers the protected rule for an exec, whose
// own path names no container. Reading one stays available, as reading its container
// does, because an exec acts on that container and not on itself.
func TestProtectedServiceCannotBeExecutedIn(t *testing.T) {
	base, _, inspector := protectedFixture()
	// Every service of that fixture declares a user, which an exec has to run as too.
	user := base.project.Services["proxy"].User
	p := &Policy{
		project:   base.project,
		protected: base.protected,
		inspect: execInspector{stubInspector: inspector, execs: map[string]ExecInfo{
			protectedExecID: {ContainerID: "proxy",
				ProcessConfig: &ExecProcessConfig{Privileged: &unprivileged, User: user}},
			unprotectedExecID: {ContainerID: "runner",
				ProcessConfig: &ExecProcessConfig{Privileged: &unprivileged, User: user}},
		}},
		commands: DefaultCommands(),
	}

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/v1.51/containers/proxy/exec", `{"Cmd":["true"]}`},
		{"POST", "/v1.51/exec/" + protectedExecID + "/start", `{"Detach":true,"Tty":false}`},
	} {
		_, err := authorize(t, p, tc.method, tc.path, tc.body)
		pe, ok := Inspect(err)
		if !ok {
			t.Fatalf("%s %s must be denied, got %v", tc.method, tc.path, err)
		}
		if pe.Service != "proxy" {
			t.Errorf("denial named service %q, want the protected one", pe.Service)
		}
		if want := "is not allowed for a protected service"; !strings.Contains(pe.Detail, want) {
			t.Errorf("refusal = %q, want it to mention %q", pe.Detail, want)
		}
	}

	decision, err := authorize(t, p, "GET", "/v1.51/exec/"+protectedExecID+"/json", "")
	if err != nil {
		t.Fatalf("reading an exec of a protected container must remain available, got %v", err)
	}
	if decision.Service != "proxy" {
		t.Errorf("resolved service %q, want proxy", decision.Service)
	}

	// The deployment this proxy exists for mounts only its own socket, so its
	// containers stay executable.
	if _, err := authorize(t, p, "POST", "/v1.51/exec/"+unprotectedExecID+"/start",
		`{"Detach":true,"Tty":false}`); err != nil {
		t.Errorf("an exec of a service holding only the restricted socket must be allowed, got %v", err)
	}
}
