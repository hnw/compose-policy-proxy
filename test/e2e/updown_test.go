package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const upDownCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "echo UP-OK; sleep 600"]
    volumes:
      - cache:/cache
  fixed-name:
    image: %IMAGE%
    command: ["sh", "-c", "sleep 600"]
    container_name: fixed-name
volumes:
  cache: {}
`

func newUpDownProject(t *testing.T) *project {
	t.Helper()
	p := newProject(t, render(upDownCompose, testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	return p
}

func TestUpAndDownThroughTheProxy(t *testing.T) {
	p := newUpDownProject(t)
	h := startProxy(t, p)

	h.mustCompose("up", "-d")
	id := p.containerForService(t, "app")
	if !h.isRunning(id) {
		t.Fatal("docker compose up -d did not start the container")
	}
	h.proxy.requireLogContains(t, "endpoint=/containers/create")
	h.proxy.requireLogContains(t, "endpoint=/networks/create")

	h.mustCompose("down")
	if ids := projectContainers(t, p); len(ids) != 0 {
		t.Errorf("docker compose down left containers behind: %v", ids)
	}
	if !networkAbsent(t, p.name+"_default") {
		t.Errorf("docker compose down left the project's own network behind")
	}
	h.proxy.requireLogContains(t, "endpoint=/networks/{id}")
}

func TestUpRecreatesAContainer(t *testing.T) {
	p := newUpDownProject(t)
	h := startProxy(t, p)

	h.mustCompose("up", "-d")
	before := p.containerForService(t, "app")
	fixedBefore := p.containerForService(t, "fixed-name")

	h.mustCompose("up", "-d", "--force-recreate")
	after := p.containerForService(t, "app")
	if before == after {
		t.Fatal("docker compose up did not replace the container")
	}
	if !h.isRunning(after) {
		t.Fatal("the recreated container is not running")
	}
	if fixedAfter := p.containerForService(t, "fixed-name"); fixedAfter == fixedBefore {
		t.Fatal("docker compose up did not replace the container of the service with a container_name")
	}
	h.proxy.requireLogContains(t, "endpoint=/containers/{id}/rename")
	if ids := projectContainers(t, p); len(ids) != 2 {
		t.Errorf("the recreation left %d containers behind, want 2: %v", len(ids), ids)
	}
}

const upDownExternalCompose = `services:
  app:
    image: %IMAGE%
    command: ["sh", "-c", "sleep 600"]
    networks:
      - external
  helper:
    image: %IMAGE%
    command: ["sh", "-c", "sleep 600"]
networks:
  external:
    external: true
    name: %EXTERNAL%
`

func TestDownRemovesOnlyTheNetworksTheProjectOwns(t *testing.T) {
	external := "cpp-e2e-external-" + filepath.Base(projectTempDir(t))
	mustRunOnEngine(t, dockerHost(t), "network", "create", external)
	t.Cleanup(func() {
		mustRunOnEngine(t, dockerHost(t), "network", "rm", external)
	})

	p := newProject(t, render(strings.ReplaceAll(upDownExternalCompose, "%EXTERNAL%", external), testImage), nil)
	t.Cleanup(func() { p.cleanup(t) })
	h := startProxy(t, p)

	h.mustCompose("up", "-d")
	h.mustCompose("down")

	if !networkAbsent(t, p.name+"_default") {
		t.Errorf("the project's own network was not removed")
	}
	if networkAbsent(t, external) {
		t.Errorf("the external network %q was removed by a project that does not own it", external)
	}
}

func TestUpAndDownRefuseAProtectedService(t *testing.T) {
	p, h := newProtectedProject(t)

	out := h.mustDenyCompose("up", "-d")
	if !strings.Contains(out, "container creation is not allowed for a protected service") {
		t.Errorf("expected a protected-service refusal from up, got:\n%s", out)
	}
	if ids := projectContainersForService(t, p, "policy-proxy"); len(ids) != 0 {
		t.Errorf("a protected service container was created anyway: %v", ids)
	}

	h.composeOnEngine("up", "-d", "policy-proxy")
	id := p.containerForService(t, "policy-proxy")
	if out := h.mustDenyCompose("down"); !strings.Contains(out, "compose-policy-proxy") {
		t.Errorf("expected down to be refused, got:\n%s", out)
	}
	if !h.isRunning(id) {
		t.Error("a protected container was stopped or removed despite the refusal")
	}
}

func networkAbsent(t *testing.T, name string) bool {
	t.Helper()
	cmd := exec.Command("docker", "network", "ls", "--filter", "name=^"+name+"$", "--format", "{{.Name}}")
	cmd.Env = withEnv(os.Environ(), "DOCKER_HOST", "unix://"+dockerHost(t))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list networks: %v", err)
	}
	return strings.TrimSpace(string(out)) == ""
}
