package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// `exec` runs a command inside a container that already exists, so the host brings one
// up first: the proxy does not create service containers.

const execCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "sleep 600"]
  asuser:
    image: %IMAGE%
    user: "1000:1000"
    command: ["sh", "-c", "sleep 600"]
`

func newExecProject(t *testing.T, extraArgs ...string) (*project, *harness) {
	t.Helper()
	p := newProject(t, render(execCompose, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p, extraArgs...)
	h.composeOnEngine("up", "-d", "app")
	return p, h
}

func TestExecThroughTheProxy(t *testing.T) {
	_, h := newExecProject(t)

	out := h.mustCompose("exec", "-T", "app", "sh", "-c", "echo EXEC-OK; id -u")
	if !strings.Contains(out, "EXEC-OK") {
		t.Errorf("expected the exec to run in the container, got:\n%s", out)
	}
	for _, endpoint := range []string{"/containers/{id}/exec", "/exec/{id}/start", "/exec/{id}/json"} {
		h.proxy.requireLogContains(t, "endpoint="+endpoint)
	}
}

// The exit status comes back from the exec inspect the client reads after the stream
// ends, so a command that fails has to fail the same way it does without the proxy.
func TestExecReportsTheCommandExitCode(t *testing.T) {
	_, h := newExecProject(t)

	_, err := h.compose("exec", "-T", "app", "false")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("a failing exec must fail the client too, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
	}
}

func TestExecCarriesStdin(t *testing.T) {
	_, h := newExecProject(t)

	out, err := h.composeWithInput("piped-through-the-proxy\n", "exec", "-T", "app", "cat")
	if err != nil {
		t.Fatalf("exec with stdin failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(out, "piped-through-the-proxy") {
		t.Errorf("stdin did not reach the container, got:\n%s", out)
	}
}

// The Compose client only allocates a terminal for a command that has one, so this
// runs through `script`, which is the portable way to give the test one.
func TestExecInATerminal(t *testing.T) {
	_, h := newExecProject(t)

	out, err := h.composeExecInATerminal("exec", "app", "tty")
	if err != nil {
		t.Fatalf("exec in a terminal failed: %v\noutput:\n%s", err, out)
	}
	// The same command reports that it has no terminal when the client is not one,
	// so a device path is what shows the exec was given one.
	if !strings.Contains(out, "/dev/pts") {
		t.Errorf("expected the exec to have a terminal, got:\n%s", out)
	}
}

// A detached start answers with an empty body, so forwarding it as a stream would hold
// the client on a connection with nothing to read.
func TestExecDetached(t *testing.T) {
	_, h := newExecProject(t)

	h.mustCompose("exec", "-d", "app", "sh", "-c", "sleep 0.2; touch /tmp/detached-ran")

	out := h.mustCompose("exec", "-T", "app", "sh", "-c",
		"i=0; while [ ! -f /tmp/detached-ran ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done;"+
			"test -f /tmp/detached-ran && echo DETACHED-OK")
	if !strings.Contains(out, "DETACHED-OK") {
		t.Errorf("the detached exec did not run, got:\n%s", out)
	}
}

func TestExecIsRefusedWithoutItsCommand(t *testing.T) {
	_, h := newExecProject(t, "--allow-command=run,start,stop")

	out := h.mustDenyCompose("exec", "-T", "app", "true")
	if !strings.Contains(out, "compose exec is not available") {
		t.Errorf("expected the refusal to name the command, got:\n%s", out)
	}
}

// The privilege of an exec is read from the Engine rather than from anything the proxy
// saw when it was created, so an exec created on the Engine itself is judged the same
// way as one created through the proxy. This also shows the Engine reports the privilege
// at all, which is what the check rests on.
func TestExecCreatedOutsideTheProxyIsJudgedByTheEngine(t *testing.T) {
	p, h := newExecProject(t)
	container := p.containerForService(t, "app")

	privileged := createExecOnEngine(t, h.dockerHost, container,
		`{"Cmd":["true"],"AttachStdout":true,"Privileged":true}`)
	resp := doRequest(t, h.socket, "POST", "/v1.51/exec/"+privileged+"/start", `{"Detach":true,"Tty":false}`)
	if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Privileged") {
		t.Fatalf("starting an exec created with privilege outside the proxy = %d\n%s",
			resp.StatusCode, body)
	}

	plain := createExecOnEngine(t, h.dockerHost, container, `{"Cmd":["true"],"AttachStdout":true}`)
	resp = doRequest(t, h.socket, "POST", "/v1.51/exec/"+plain+"/start", `{"Detach":true,"Tty":false}`)
	if body := readBody(t, resp); resp.StatusCode != http.StatusOK {
		t.Fatalf("starting an unprivileged exec the Engine holds = %d\n%s", resp.StatusCode, body)
	}
}

// An exec runs as the user its container runs as, which is what the Engine reports for
// an exec created without one. A service that declares a user is therefore executable,
// while an exec that asks for a user of its own is refused.
func TestExecRunsAsTheContainerUser(t *testing.T) {
	p, h := newExecProject(t)
	h.composeOnEngine("up", "-d", "asuser")

	if out := h.mustCompose("exec", "-T", "asuser", "id", "-u"); !strings.Contains(out, "1000") {
		t.Errorf("expected the exec to run as the container's user, got:\n%s", out)
	}

	asRoot := createExecOnEngine(t, h.dockerHost, p.containerForService(t, "asuser"),
		`{"Cmd":["true"],"AttachStdout":true,"User":"root"}`)
	resp := doRequest(t, h.socket, "POST", "/v1.51/exec/"+asRoot+"/start", `{"Detach":true,"Tty":false}`)
	if body := readBody(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "User") {
		t.Fatalf("starting an exec created for another user = %d\n%s", resp.StatusCode, body)
	}
}

// createExecOnEngine creates an exec without starting it, which is the state a client
// through the proxy would find a request about.
func createExecOnEngine(t *testing.T, host, container, body string) string {
	t.Helper()
	resp := doRequest(t, host, "POST", "/v1.51/containers/"+container+"/exec", body)
	payload := readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("the Engine refused the exec create: %d %s", resp.StatusCode, payload)
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal([]byte(payload), &created); err != nil || created.ID == "" {
		t.Fatalf("the Engine created no exec to authorize: %q", payload)
	}
	return created.ID
}

// A protected service holds the Engine socket itself, so an exec inside it is a way
// around the proxy even though it names no container in its own path.
func TestProtectedServiceCannotBeExecutedIn(t *testing.T) {
	_, h := newProtectedProject(t)
	h.composeOnEngine("up", "-d", "policy-proxy")

	out := h.mustDenyCompose("exec", "-T", "policy-proxy", "true")
	if !strings.Contains(out, "is not allowed for a protected service") {
		t.Errorf("expected a protected-service refusal, got:\n%s", out)
	}
	h.proxy.requireLogContains(t, "service=policy-proxy")
}

// composeExecInATerminal runs a compose command under `script`, which allocates the
// terminal its client asks for. The two implementations spell the command differently.
func (h *harness) composeExecInATerminal(args ...string) (string, error) {
	h.t.Helper()
	compose := append([]string{"docker", "compose"}, args...)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		cmd = exec.CommandContext(ctx, "script", append([]string{"-q", "/dev/null"}, compose...)...)
	} else {
		cmd = exec.CommandContext(ctx, "script", "-q", "-c", strings.Join(compose, " "), "/dev/null")
	}
	cmd.Dir = h.project.dir
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.socket)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}
