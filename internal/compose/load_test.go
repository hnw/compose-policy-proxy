package compose_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadResolvesProjectFromWorkingDirectory(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": `name: demo
services:
  app:
    image: alpine:3.20
    volumes:
      - ./config:/app/config:ro
      - cache:/cache
    networks:
      - frontend
networks:
  frontend:
volumes:
  cache:
`,
	})

	project, err := compose.Load(context.Background(), dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if project.Name != "demo" {
		t.Errorf("project name = %q, want %q", project.Name, "demo")
	}
	if project.WorkingDir != dir {
		t.Errorf("working dir = %q, want %q", project.WorkingDir, dir)
	}
	if _, err := compose.Service(project, "app"); err != nil {
		t.Errorf("service app not found: %v", err)
	}
}

func TestLoadResolvesResourceNames(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": `name: demo
services:
  app:
    image: alpine:3.20
    volumes: [cache:/cache]
    networks: [shared]
networks:
  managed:
  shared:
    external: true
volumes:
  cache:
  prefixed:
    name: custom-cache
`,
	})
	project, err := compose.Load(context.Background(), dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	networks := map[string]string{
		"managed": "demo_managed",
		"shared":  "shared",
	}
	for key, want := range networks {
		got, err := compose.NetworkName(project, key)
		if err != nil {
			t.Fatalf("network %q: %v", key, err)
		}
		if got != want {
			t.Errorf("network %q = %q, want %q", key, got, want)
		}
	}

	volumes := map[string]string{
		"cache":    "demo_cache",
		"prefixed": "custom-cache",
	}
	for key, want := range volumes {
		got, err := compose.VolumeName(project, key)
		if err != nil {
			t.Fatalf("volume %q: %v", key, err)
		}
		if got != want {
			t.Errorf("volume %q = %q, want %q", key, got, want)
		}
	}
}

func TestBindSourceResolution(t *testing.T) {
	project := &types.Project{Name: "demo", WorkingDir: "/opt/app"}
	cases := map[string]string{
		"./config":       "/opt/app/config",
		"config":         "/opt/app/config",
		"./a/b/../c":     "/opt/app/a/c",
		"/absolute/path": "/absolute/path",
	}
	for in, want := range cases {
		got, err := compose.BindSource(project, in)
		if err != nil {
			t.Fatalf("BindSource(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("BindSource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageNameDefaultsToProjectServiceName(t *testing.T) {
	project := &types.Project{Name: "demo"}
	if got := compose.ImageName(project, types.ServiceConfig{Name: "app", Image: "alpine:3.20"}); got != "alpine:3.20" {
		t.Errorf("explicit image changed to %q", got)
	}
	if got := compose.ImageName(project, types.ServiceConfig{Name: "app"}); got != "demo_app" {
		t.Errorf("implicit image = %q, want demo_app", got)
	}
}

func TestServicesIncludesProfileGatedServices(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": `name: demo
services:
  always:
    image: alpine:3.20
  gated:
    image: busybox
    profiles: [extra]
`,
	})
	project, err := compose.Load(context.Background(), dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := compose.Service(project, "gated"); err != nil {
		t.Errorf("a profile-gated service must stay in the policy scope: %v", err)
	}
	all := compose.Services(project)
	if len(all) != 2 {
		t.Errorf("expected both services, got %d", len(all))
	}
}
