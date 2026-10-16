package policy

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// These deployments are real Compose files, since what matters is what the resolver
// makes of a mount. protectedFor loads one and returns the services it protects.
func protectedFor(t *testing.T, yaml, dockerHost, restrictedSocket string) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("name: demo\n"+yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	project, err := compose.Load(context.Background(), dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return resolveProtectedServices(project, dockerHost, restrictedSocket).names()
}

func assertProtected(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("protected services = %v, want %v", got, want)
	}
}

func TestBindMountOfTheDockerSocketIsProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
  proxy:
    image: alpine:3.20
    volumes:
      - `+hostSocket+`:`+hostSocket+`
`, hostSocket, proxySocket)
	assertProtected(t, got, "proxy")
}

func TestTheProxySocketBindIsNotProtected(t *testing.T) {
	// The proxy runs on the host and hands its socket to the application at the
	// usual Docker socket path, so that container reaches the Engine only through it.
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    volumes:
      - `+proxySocket+`:`+hostSocket+`
`, hostSocket, proxySocket)
	assertProtected(t, got)
}

func TestNamedVolumeAtTheSocketPathIsNotProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    volumes:
      - socket:/var/run/docker.sock
volumes:
  socket:
`, hostSocket, proxySocket)
	assertProtected(t, got)
}

func TestBindMountElsewhereIsNotProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    volumes:
      - ./data:/data
      - `+hostSocket+`:/opt/daemon.sock
`, hostSocket, proxySocket)
	assertProtected(t, got)
}

func TestOneMatchingMountAmongManyProtectsTheService(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    volumes:
      - ./data:/data:ro
      - cache:/cache
      - `+hostSocket+`:`+hostSocket+`
      - /host/etc:/etc:ro
  other:
    image: alpine:3.20
volumes:
  cache:
`, hostSocket, proxySocket)
	assertProtected(t, got, "app")
}

func TestDetectionFollowsTheConfiguredSocketPaths(t *testing.T) {
	// In rootless Docker the Engine listens elsewhere, and so does the proxy.
	const (
		rootlessHost  = "/run/user/1000/docker.sock"
		rootlessProxy = "/run/user/1000/compose-policy-proxy/docker.sock"
	)
	got := protectedFor(t, `services:
  proxy:
    image: alpine:3.20
    volumes:
      - type: bind
        source: `+rootlessHost+`
        target: /var/run/docker.sock
  app:
    image: alpine:3.20
    volumes:
      - `+rootlessHost+`:`+rootlessHost+`
  runner:
    image: alpine:3.20
    volumes:
      - `+rootlessProxy+`:`+hostSocket+`
`, rootlessHost, rootlessProxy)
	assertProtected(t, got, "app")
}

func TestPathCleanupDoesNotChangeTheDecision(t *testing.T) {
	// Compose keeps whatever separators the file used. The rule compares cleaned
	// paths, so a redundant separator is not a way to look different.
	got := protectedFor(t, `services:
  proxy:
    image: alpine:3.20
    volumes:
      - type: bind
        source: `+hostSocket+`/
        target: `+hostSocket+`/
`, hostSocket, proxySocket)
	assertProtected(t, got, "proxy")
}

func TestTmpfsAtTheSocketPathIsNotProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    tmpfs:
      - /var/run/docker.sock
`, hostSocket, proxySocket)
	assertProtected(t, got)
}

func TestTheSocketPathAtAnotherDestinationIsNotProtected(t *testing.T) {
	// A documented limitation, pinned so it stays one. A parent directory that
	// contains the socket does reach Docker, and the rule claims otherwise nothing.
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    volumes:
      - /var/run:/host/run
`, hostSocket, proxySocket)
	assertProtected(t, got)
}

func TestTheDestinationDecidesRatherThanTheSource(t *testing.T) {
	// The proxy does not probe what a host path is. A bind onto the path Docker is
	// served at is protected, because the destination is where a client reaches it.
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    volumes:
      - ./docker.sock:/var/run/docker.sock
`, hostSocket, proxySocket)
	assertProtected(t, got, "app")
}

func TestProfileGatedServicesStayProtected(t *testing.T) {
	// A service the proxy cannot see is a service it could not refuse.
	got := protectedFor(t, `services:
  proxy:
    image: alpine:3.20
    profiles: [ops]
    volumes:
      - `+hostSocket+`:`+hostSocket+`
`, hostSocket, proxySocket)
	assertProtected(t, got, "proxy")
}

// A secret reaches the container as a read-only bind, which is what a real
// `docker compose` sends, so it can carry the socket without appearing in volumes.
func TestSecretDeliveredSocketIsProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    secrets:
      - source: sock
        target: `+hostSocket+`
  elsewhere:
    image: alpine:3.20
    secrets:
      - source: sock
        target: /opt/daemon.sock
secrets:
  sock:
    file: `+hostSocket+`
`, hostSocket, proxySocket)
	assertProtected(t, got, "app")
}

// The same for configs, which Compose also materializes as a bind.
func TestConfigDeliveredSocketIsProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    configs:
      - source: sock
        target: `+hostSocket+`
configs:
  sock:
    file: `+hostSocket+`
`, hostSocket, proxySocket)
	assertProtected(t, got, "app")
}

// A secret delivered in the environment is not a mount at all.
func TestEnvironmentSecretIsNotProtected(t *testing.T) {
	got := protectedFor(t, `services:
  app:
    image: alpine:3.20
    secrets:
      - source: sock
secrets:
  sock:
    environment: SOCK
`, hostSocket, proxySocket)
	assertProtected(t, got)
}

// TestSocketDeliveredByAnyRouteIsRefusedWhateverLabelTheRequestClaims is the regression
// this rule exists for. Compose sends one mount for a socket under volumes or from a secret.
func TestSocketDeliveredByAnyRouteIsRefusedWhateverLabelTheRequestClaims(t *testing.T) {
	project := &types.Project{
		Name:       projectName,
		WorkingDir: projectDir,
		Secrets:    types.Secrets{"sock": {File: hostSocket}},
		Services: types.Services{
			"via-volumes": {
				Name:  "via-volumes",
				Image: "alpine:3.20",
				Volumes: []types.ServiceVolumeConfig{{
					Type: types.VolumeTypeBind, Source: hostSocket, Target: hostSocket,
					ReadOnly: true, Bind: &types.ServiceVolumeBind{},
				}},
			},
			"via-secret": {
				Name:    "via-secret",
				Image:   "alpine:3.20",
				Secrets: []types.ServiceSecretConfig{{Source: "sock", Target: hostSocket}},
			},
		},
	}
	p, err := New(Config{
		Project:         project,
		DockerHost:      hostSocket,
		Listen:          proxySocket,
		Engine:          stubInspector{},
		AllowedCommands: DefaultCommands(),
	})
	if err != nil {
		t.Fatalf("build policy: %v", err)
	}

	// The request Compose sends for either service, with the socket as a read-only
	// bind through the Mount API.
	req := &container.CreateRequest{
		Config: &container.Config{Image: "alpine:3.20"},
		HostConfig: &container.HostConfig{
			NetworkMode: "none",
			Mounts: []mount.Mount{{
				Type:        mount.TypeBind,
				Source:      hostSocket,
				Target:      hostSocket,
				ReadOnly:    true,
				BindOptions: &mount.BindOptions{},
			}},
		},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{}},
	}
	for _, name := range []string{"via-volumes", "via-secret"} {
		if err := compareService(project, project.Services[name], req, modeCreate); err != nil {
			t.Fatalf("one request should match %s whatever route it declares the socket by, got %v", name, err)
		}
	}

	u, err := url.Parse("http://docker/v1.51/containers/create")
	if err != nil {
		t.Fatal(err)
	}
	for _, claim := range []string{"via-volumes", "via-secret"} {
		t.Run(claim, func(t *testing.T) {
			claimed := *req
			config := *req.Config
			config.Labels = map[string]string{
				LabelProject: projectName,
				LabelService: claim,
				LabelOneoff:  oneoffLabelValue,
			}
			claimed.Config = &config
			body, err := json.Marshal(&claimed)
			if err != nil {
				t.Fatalf("encode create request: %v", err)
			}

			decision, err := p.Authorize(t.Context(), &Request{Method: "POST", URL: u, Body: body})
			pe, ok := Inspect(err)
			if !ok || pe.Service != claim {
				t.Fatalf("a request carrying the Docker socket was authorized as %+v: %v", decision, err)
			}
			if !strings.Contains(pe.Detail, "mounts the Docker socket") {
				t.Fatalf("the refusal must be the protected-service one, got %q", pe.Detail)
			}
		})
	}
}
