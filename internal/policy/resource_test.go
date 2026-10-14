package policy

import (
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// resourceProject declares a managed and an external network and volume, which
// covers prefixing, external resources, drivers, IPAM and management labels.
func resourceProject() *types.Project {
	return &types.Project{
		Name:       "demo",
		WorkingDir: "/opt/app",
		Networks: types.Networks{
			"default":  {Name: "demo_default"},
			"frontend": {Name: "demo_frontend"},
			"named":    {Name: "custom-frontend-name", Driver: "bridge", DriverOpts: types.Options{"com.example.opt": "value"}},
			"shared":   {Name: "shared-net", External: true},
			"ipam_net": {
				Name:   "demo_ipam_net",
				Driver: "bridge",
				Ipam: types.IPAMConfig{
					Driver: "default",
					Config: []*types.IPAMPool{{
						Subnet:             "172.30.0.0/24",
						Gateway:            "172.30.0.1",
						IPRange:            "172.30.0.0/25",
						AuxiliaryAddresses: types.Mapping{"host": "172.30.0.2"},
					}},
					Options: types.Options{"foo": "bar"},
				},
			},
			"internal_net": {Name: "demo_internal_net", Internal: true, Attachable: true},
		},
		Volumes: types.Volumes{
			"cache":  {Name: "demo_cache", Driver: "local"},
			"named":  {Name: "custom-cache-name", Driver: "local", DriverOpts: types.Options{"type": "nfs"}},
			"shared": {Name: "shared-vol", External: true},
		},
	}
}

func TestProjectPrefixIsUsedForNames(t *testing.T) {
	p := resourceProject()
	for key, want := range map[string]string{
		"default":  "demo_default",
		"frontend": "demo_frontend",
	} {
		got, err := compose.NetworkName(p, key)
		if err != nil {
			t.Fatalf("network %q: %v", key, err)
		}
		if got != want {
			t.Errorf("network %q resolved to %q, want %q", key, got, want)
		}
	}
}

func TestExplicitNameOverridesPrefix(t *testing.T) {
	p := resourceProject()
	if got, _ := compose.NetworkName(p, "named"); got != "custom-frontend-name" {
		t.Errorf("explicit name ignored: got %q", got)
	}
	if got, _ := compose.VolumeName(p, "named"); got != "custom-cache-name" {
		t.Errorf("explicit name ignored: got %q", got)
	}
}

func TestDeclaredNetworksAndVolumesAreRecognised(t *testing.T) {
	p := resourceProject()
	for _, name := range []string{
		"demo_default", "demo_frontend", "custom-frontend-name", "shared-net", "demo_ipam_net", "demo_internal_net",
	} {
		if !networkIsDeclared(p, name) {
			t.Errorf("network %q should be recognised as declared", name)
		}
	}
	for _, name := range []string{"other_net", "demo_cache_other", ""} {
		if networkIsDeclared(p, name) {
			t.Errorf("network %q should not be recognised", name)
		}
	}
	for _, name := range []string{"demo_cache", "custom-cache-name", "shared-vol"} {
		if !volumeIsDeclared(p, name) {
			t.Errorf("volume %q should be recognised as declared", name)
		}
	}
	if volumeIsDeclared(p, "someone_elses_volume") {
		t.Error("an undeclared volume was recognised")
	}
}

func TestMatchNetworkCreateAcceptsDeclaredNetwork(t *testing.T) {
	p := resourceProject()
	req := network.CreateRequest{
		Name: "demo_frontend",
		CreateOptions: network.CreateOptions{
			Driver: "",
			Labels: map[string]string{
				LabelProject: "demo",
				LabelNetwork: "frontend",
			},
		},
	}
	key, err := matchNetworkCreate(p, req)
	if err != nil {
		t.Fatalf("expected the request to be allowed, got %v", err)
	}
	if key != "frontend" {
		t.Errorf("expected key %q, got %q", "frontend", key)
	}
}

func TestMatchNetworkCreateChecksDriverAndOptions(t *testing.T) {
	p := resourceProject()
	base := func() network.CreateRequest {
		return network.CreateRequest{
			Name: "custom-frontend-name",
			CreateOptions: network.CreateOptions{
				Driver:  "bridge",
				Options: map[string]string{"com.example.opt": "value"},
				Labels: map[string]string{
					LabelProject: "demo",
					LabelNetwork: "named",
				},
			},
		}
	}
	if _, err := matchNetworkCreate(p, base()); err != nil {
		t.Fatalf("baseline request should be allowed, got %v", err)
	}

	t.Run("driver changed", func(t *testing.T) {
		req := base()
		req.Driver = "overlay"
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("a changed driver was accepted")
		}
	})
	t.Run("driver option changed", func(t *testing.T) {
		req := base()
		req.Options = map[string]string{"com.example.opt": "other"}
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("a changed driver option was accepted")
		}
	})
	t.Run("driver option removed", func(t *testing.T) {
		req := base()
		req.Options = nil
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("a removed driver option was accepted")
		}
	})
}

func TestMatchNetworkCreateChecksIPAM(t *testing.T) {
	p := resourceProject()
	base := func() network.CreateRequest {
		return network.CreateRequest{
			Name: "demo_ipam_net",
			CreateOptions: network.CreateOptions{
				Driver: "bridge",
				Labels: map[string]string{
					LabelProject: "demo",
					LabelNetwork: "ipam_net",
				},
				IPAM: &network.IPAM{
					Driver:  "default",
					Options: map[string]string{"foo": "bar"},
					Config: []network.IPAMConfig{{
						Subnet:     "172.30.0.0/24",
						Gateway:    "172.30.0.1",
						IPRange:    "172.30.0.0/25",
						AuxAddress: map[string]string{"host": "172.30.0.2"},
					}},
				},
			},
		}
	}
	if _, err := matchNetworkCreate(p, base()); err != nil {
		t.Fatalf("baseline request should be allowed, got %v", err)
	}

	for name, mutate := range map[string]func(*network.CreateRequest){
		"subnet changed":      func(r *network.CreateRequest) { r.IPAM.Config[0].Subnet = "10.0.0.0/24" },
		"gateway changed":     func(r *network.CreateRequest) { r.IPAM.Config[0].Gateway = "10.0.0.1" },
		"ip range changed":    func(r *network.CreateRequest) { r.IPAM.Config[0].IPRange = "10.0.0.0/25" },
		"aux address changed": func(r *network.CreateRequest) { r.IPAM.Config[0].AuxAddress["host"] = "10.0.0.2" },
		"pool added": func(r *network.CreateRequest) {
			r.IPAM.Config = append(r.IPAM.Config, network.IPAMConfig{Subnet: "10.1.0.0/24"})
		},
		"ipam options changed": func(r *network.CreateRequest) { r.IPAM.Options = map[string]string{"foo": "other"} },
	} {
		t.Run(name, func(t *testing.T) {
			req := base()
			mutate(&req)
			if _, err := matchNetworkCreate(p, req); err == nil {
				t.Errorf("a request with %s was accepted", name)
			}
		})
	}
}

// TestMatchNetworkCreateRefusesAnUndeclaredIPAM covers a network whose Compose
// definition carries no IPAM, so a driver in the request is the client's own choice.
func TestMatchNetworkCreateRefusesAnUndeclaredIPAM(t *testing.T) {
	p := resourceProject()
	allowed := []struct {
		name string
		ipam *network.IPAM
	}{
		{"no IPAM at all, as compose sends it", nil},
		{"the built-in driver, which is what the engine substitutes", &network.IPAM{Driver: "default"}},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			req := network.CreateRequest{
				Name: "demo_frontend",
				CreateOptions: network.CreateOptions{
					Labels: map[string]string{
						LabelProject: "demo",
						LabelNetwork: "frontend",
					},
					IPAM: tc.ipam,
				},
			}
			if _, err := matchNetworkCreate(p, req); err != nil {
				t.Errorf("a request with %s must be accepted, got %v", tc.name, err)
			}
		})
	}

	denied := []struct {
		name  string
		field string
		ipam  *network.IPAM
	}{
		{"an undeclared driver", "IPAM.Driver", &network.IPAM{Driver: "custom-ipam"}},
		{"undeclared driver options", "IPAM.Options", &network.IPAM{Options: map[string]string{"foo": "bar"}}},
		{"options next to the built-in driver", "IPAM.Options", &network.IPAM{
			Driver:  "default",
			Options: map[string]string{"foo": "bar"},
		}},
	}
	for _, tc := range denied {
		t.Run(tc.name, func(t *testing.T) {
			req := network.CreateRequest{
				Name: "demo_frontend",
				CreateOptions: network.CreateOptions{
					Labels: map[string]string{
						LabelProject: "demo",
						LabelNetwork: "frontend",
					},
					IPAM: tc.ipam,
				},
			}
			_, err := matchNetworkCreate(p, req)
			if pe, ok := Inspect(err); !ok || pe.Field != tc.field {
				t.Fatalf("a request with %s must be refused on %s, got %v", tc.name, tc.field, err)
			}
		})
	}
}

func TestMatchNetworkCreateDeniesExternalAndForeign(t *testing.T) {
	p := resourceProject()

	t.Run("external network", func(t *testing.T) {
		req := network.CreateRequest{Name: "shared-net"}
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("creating an external network was accepted")
		}
	})
	t.Run("foreign network", func(t *testing.T) {
		req := network.CreateRequest{Name: "someone_elses_net"}
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("creating a network outside the project was accepted")
		}
	})
	t.Run("missing project label", func(t *testing.T) {
		req := network.CreateRequest{Name: "demo_frontend"}
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("creating a network without the project management label was accepted")
		}
	})
	t.Run("ingress network", func(t *testing.T) {
		req := network.CreateRequest{
			Name:          "demo_frontend",
			CreateOptions: network.CreateOptions{Ingress: true},
		}
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("creating an ingress network was accepted")
		}
	})
	t.Run("swarm scope", func(t *testing.T) {
		req := network.CreateRequest{
			Name:          "demo_frontend",
			CreateOptions: network.CreateOptions{Scope: "global"},
		}
		if _, err := matchNetworkCreate(p, req); err == nil {
			t.Error("a network with an undeclared scope was accepted")
		}
	})
}

func TestMatchNetworkCreateChecksInternalAndAttachable(t *testing.T) {
	p := resourceProject()
	req := network.CreateRequest{
		Name: "demo_internal_net",
		CreateOptions: network.CreateOptions{
			Internal:   true,
			Attachable: true,
			Labels: map[string]string{
				LabelProject: "demo",
				LabelNetwork: "internal_net",
			},
		},
	}
	if _, err := matchNetworkCreate(p, req); err != nil {
		t.Fatalf("baseline request should be allowed, got %v", err)
	}
	req.Internal = false
	if _, err := matchNetworkCreate(p, req); err == nil {
		t.Error("a changed internal flag was accepted")
	}
}

func TestMatchVolumeCreate(t *testing.T) {
	p := resourceProject()
	base := func() volume.CreateOptions {
		return volume.CreateOptions{
			Name:       "custom-cache-name",
			Driver:     "local",
			DriverOpts: map[string]string{"type": "nfs"},
			Labels: map[string]string{
				LabelProject: "demo",
				LabelVolume:  "named",
			},
		}
	}
	if _, err := matchVolumeCreate(p, base()); err != nil {
		t.Fatalf("baseline request should be allowed, got %v", err)
	}

	t.Run("driver changed", func(t *testing.T) {
		req := base()
		req.Driver = "tmpfs"
		if _, err := matchVolumeCreate(p, req); err == nil {
			t.Error("a changed driver was accepted")
		}
	})
	t.Run("driver option changed", func(t *testing.T) {
		req := base()
		req.DriverOpts = map[string]string{"type": "other"}
		if _, err := matchVolumeCreate(p, req); err == nil {
			t.Error("a changed driver option was accepted")
		}
	})
	t.Run("external volume", func(t *testing.T) {
		if _, err := matchVolumeCreate(p, volume.CreateOptions{Name: "shared-vol"}); err == nil {
			t.Error("creating an external volume was accepted")
		}
	})
	t.Run("foreign volume", func(t *testing.T) {
		if _, err := matchVolumeCreate(p, volume.CreateOptions{Name: "someone_elses_volume"}); err == nil {
			t.Error("creating a volume outside the project was accepted")
		}
	})
	t.Run("missing project label", func(t *testing.T) {
		req := base()
		req.Labels = nil
		if _, err := matchVolumeCreate(p, req); err == nil {
			t.Error("creating a volume without the project management label was accepted")
		}
	})
	t.Run("cluster volume", func(t *testing.T) {
		req := base()
		req.ClusterVolumeSpec = &volume.ClusterVolumeSpec{}
		if _, err := matchVolumeCreate(p, req); err == nil {
			t.Error("creating a cluster volume was accepted")
		}
	})
}

func TestImagePolicy(t *testing.T) {
	p := &types.Project{
		Name: "demo",
		Services: types.Services{
			"app":   {Name: "app", Image: "alpine:3.20"},
			"built": {Name: "built", Image: ""}, // resolves to demo_built
			"tool":  {Name: "tool", Image: "busybox"},
		},
	}
	for _, declared := range []string{
		"alpine:3.20",
		"docker.io/library/alpine:3.20",
		"demo_built",
		// An untagged reference is the same image as the :latest tag.
		"busybox:latest",
	} {
		if !imageDeclared(p, declared) {
			t.Errorf("image %q should be declared", declared)
		}
	}
	for _, foreign := range []string{
		// A spelled-out tag is part of the image identity.
		"alpine:3.19",
		"alpine",
		"docker.io/library/busybox:1.36",
		"evil:latest",
		"",
	} {
		if imageDeclared(p, foreign) {
			t.Errorf("image %q should not be declared", foreign)
		}
	}

	const (
		pinned = "sha256:3a3e2f8c1b0d5e7a9c4b6d8f0e2a4c6b8d0f2e4a6c8b0d2f4e6a8c0b2d4f6e8a"
		other  = "sha256:1b7d9f3a5c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0c"
	)
	r := &types.Project{
		Name: "demo",
		Services: types.Services{
			"hub":    {Name: "hub", Image: "alpine"},
			"local":  {Name: "local", Image: "localhost:5000/myapp"},
			"pinned": {Name: "pinned", Image: "localhost:5000/myapp@" + pinned},
		},
	}
	for _, declared := range []string{
		"alpine",
		"docker.io/library/alpine:latest",
		"localhost:5000/myapp:latest",
		"localhost:5000/myapp@" + pinned,
	} {
		if !imageDeclared(r, declared) {
			t.Errorf("image %q should be declared", declared)
		}
	}
	for _, foreign := range []string{
		// A registry port is not a tag, so it never stands in for one.
		"localhost:5000/myapp:1.0",
		"localhost:5000/myapp:2.0",
		// A digest pins the content, so a different digest or registry is a
		// different image.
		"localhost:5000/myapp@" + other,
		"registry.example.com/myapp@" + pinned,
		// A tag written next to a digest is part of the identity and is kept.
		"localhost:5000/myapp:1.0@" + pinned,
		"Alpine",
		"localhost:5000/myapp:",
	} {
		if imageDeclared(r, foreign) {
			t.Errorf("image %q should not be declared", foreign)
		}
	}
}

func TestPullPolicy(t *testing.T) {
	p := &types.Project{
		Name:     "demo",
		Services: types.Services{"app": {Name: "app", Image: "alpine:3.20"}},
	}
	if err := allowPull(p, "alpine:3.20", false); err != nil {
		t.Errorf("pulling a declared image should be allowed, got %v", err)
	}
	if err := allowPull(p, "busybox", false); err == nil {
		t.Error("pulling an undeclared image was allowed")
	}
	if err := allowPull(p, "alpine:3.20", true); err == nil {
		t.Error("a bulk pull was allowed")
	}
	if err := allowPull(p, "alpine:3.20,busybox", false); err == nil {
		t.Error("a multi-image pull was allowed")
	}
	if err := allowPull(p, "", false); err == nil {
		t.Error("a pull with no target was allowed")
	}
}
