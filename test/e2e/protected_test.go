package e2e

import (
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// %SOCKET% is the destination the detection rule compares a mount against. The source
// is a stand-in file because a bind mount may not be able to reach the Engine socket.
const protectedCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo APP-OK"]
  policy-proxy:
    image: %IMAGE%
    command: ["sh", "-c", "echo PROXY-OK; sleep 600"]
    volumes:
      - ./socket:%SOCKET%
  policy-proxy-once:
    image: %IMAGE%
    command: ["sh", "-c", "exit 7"]
    volumes:
      - ./socket:%SOCKET%
`

func renderProtected(tmpl, image, socket string) string {
	return strings.NewReplacer("%IMAGE%", image, "%SOCKET%", socket).Replace(tmpl)
}

func newProtectedProject(t *testing.T) (*project, *harness) {
	t.Helper()
	p := newProject(t, renderProtected(protectedCompose, testImage, dockerHost(t)),
		map[string]string{"socket": "stand-in for the engine socket"})
	t.Cleanup(func() { p.cleanup(t) })
	// Every command is allowed by default, so a refusal in these tests can only be the
	// protected rule.
	return p, startProxy(t, p)
}

// isRunning proves a denied request had no effect rather than merely failing.
func (h *harness) isRunning(id string) bool {
	h.t.Helper()
	cmd := exec.Command("docker", "inspect", "--format", "{{.State.Running}}", id)
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+h.dockerHost)
	out, err := cmd.Output()
	if err != nil {
		h.t.Fatalf("inspect container state: %v", err)
	}
	return strings.TrimSpace(string(out)) == "true"
}

func TestProtectedServiceCannotBeLaunchedThroughTheProxy(t *testing.T) {
	_, h := newProtectedProject(t)

	if out := h.mustRun("--rm", "-T", "app"); !strings.Contains(out, "APP-OK") {
		t.Errorf("an ordinary service must still run, got:\n%s", out)
	}

	out := h.mustDeny("--rm", "-T", "policy-proxy")
	if !strings.Contains(out, "container creation is not allowed for a protected service") {
		t.Errorf("expected a protected-service refusal, got:\n%s", out)
	}
	h.proxy.requireLogContains(t, `detail="container creation is not allowed for a protected service"`)
	h.proxy.requireLogContains(t, "service=policy-proxy")
}

// The unit tests enumerate every allowlisted operation, so what is left is that
// the refusals reach a real container and leave it untouched.
func TestProtectedContainerCannotBeControlledThroughTheProxy(t *testing.T) {
	p, h := newProtectedProject(t)
	h.composeOnEngine("up", "-d", "policy-proxy")
	id := p.containerForService(t, "policy-proxy")

	denied := []struct{ method, path string }{
		{"POST", "/containers/" + id + "/stop"},
		{"POST", "/containers/" + id + "/restart"},
		{"GET", "/containers/" + id + "/logs?stdout=1&stderr=1"},
		{"DELETE", "/containers/" + id + "?force=1"},
		{"POST", "/containers/" + id + "/attach?stream=1&stdout=1"},
	}
	for _, tc := range denied {
		resp := doRequest(t, h.socket, tc.method, tc.path, "")
		body := readBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403\n%s", tc.method, tc.path, resp.StatusCode, body)
		}
		if !strings.Contains(body, "is not allowed for a protected service") {
			t.Errorf("%s %s: expected a protected-service refusal, got:\n%s", tc.method, tc.path, body)
		}
	}

	if !h.isRunning(id) {
		t.Fatal("the protected container was stopped or removed despite the refusals")
	}
	h.proxy.requireLogContains(t, "detail=\"POST /containers/{id}/stop is not allowed for a protected service\"")
}

// Wait is here because it observes through a POST. What counts is the effect on the
// container, not the method.
func TestProtectedContainerStaysReadable(t *testing.T) {
	p, h := newProtectedProject(t)

	h.composeOnEngine("up", "-d", "policy-proxy-once")
	once := p.containerForService(t, "policy-proxy-once")
	resp := doRequest(t, h.socket, "GET", "/containers/"+once+"/json", "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("inspect of a protected container = %d, want 200\n%s", resp.StatusCode, body)
	}

	// Waiting is granted too, and is checked on the short-lived service because
	// wait on a container that is still running would hold the request open.
	resp = doRequest(t, h.socket, "POST", "/containers/"+once+"/wait", "")
	body = readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("wait on a protected container = %d, want 200\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "7") {
		t.Errorf("expected the container exit status, got:\n%s", body)
	}
}

// The protected services are declared alongside this one, so these requests are
// refused if the rule leaks past the service it names.
func TestOrdinaryContainerCanBeControlled(t *testing.T) {
	p, h := newProtectedProject(t)
	detachAndLeaveRunning(t, h, p, "app", "sleep", "600")
	id := p.containerForService(t, "app")

	for _, tc := range []struct{ method, path string }{
		{"POST", "/containers/" + id + "/stop?t=0"},
		{"DELETE", "/containers/" + id + "?force=1"},
	} {
		resp := doRequest(t, h.socket, tc.method, tc.path, "")
		body := readBody(t, resp)
		if resp.StatusCode == http.StatusForbidden {
			t.Errorf("%s %s was refused on an ordinary container:\n%s", tc.method, tc.path, body)
		}
		if strings.Contains(body, "protected service") {
			t.Errorf("%s %s was refused as protected:\n%s", tc.method, tc.path, body)
		}
	}
	if ids := projectContainers(t, p); len(ids) != 0 {
		t.Errorf("the ordinary container was not removed, still present: %v", ids)
	}
}
