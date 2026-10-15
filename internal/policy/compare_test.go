package policy

import (
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

// These tests pin the policy boundary from both sides. The deny cases keep the
// sensitive fields refused, the allow cases record what is forwarded on purpose.

const projectName = "demo"
const projectDir = "/opt/app"

func fixture() (*types.Project, types.ServiceConfig, *container.CreateRequest) {
	project := &types.Project{
		Name:       projectName,
		WorkingDir: projectDir,
		Networks: types.Networks{
			"frontend": {Name: "demo_frontend"},
		},
		Volumes: types.Volumes{
			"cache": {Name: "demo_cache"},
		},
	}

	service := types.ServiceConfig{
		Name:              "app",
		Image:             "alpine:3.20",
		User:              "1000:1000",
		CapAdd:            []string{"NET_ADMIN", "SYS_TIME"},
		CapDrop:           []string{"MKNOD"},
		GroupAdd:          []string{"2000", "3000"},
		Privileged:        true,
		ReadOnly:          true,
		Runtime:           "runc",
		SecurityOpt:       []string{"no-new-privileges:true"},
		Sysctls:           types.Mapping{"net.ipv4.ip_forward": "1"},
		Pid:               "host",
		Ipc:               "host",
		Cgroup:            "host",
		UserNSMode:        "keep-id",
		Uts:               "host",
		Hostname:          "app-host",
		WorkingDir:        "/app",
		Devices:           []types.DeviceMapping{{Source: "/dev/null", Target: "/dev/null", Permissions: "rwm"}},
		DeviceCgroupRules: []string{"c 1:3 mr"},
		CgroupParent:      "/docker",
		Isolation:         "default",
		VolumesFrom:       []string{"other"},
		Links:             []string{"other:alias"},
		Volumes: []types.ServiceVolumeConfig{
			{
				Type: types.VolumeTypeBind, Source: projectDir + "/config", Target: "/app/config",
				ReadOnly: true, Bind: &types.ServiceVolumeBind{CreateHostPath: true},
			},
			{Type: types.VolumeTypeVolume, Source: "cache", Target: "/cache"},
		},
		Tmpfs:    types.StringList{"/tmpmount:size=1m,mode=1777"},
		Networks: map[string]*types.ServiceNetworkConfig{"frontend": {Aliases: []string{"myalias"}}},
		Ports: []types.ServicePortConfig{
			{Target: 80, Published: "8080", Protocol: "tcp"},
			{Target: 90, Published: "9090", Protocol: "udp", HostIP: "127.0.0.1"},
		},
	}

	req := &container.CreateRequest{
		Config: &container.Config{
			Image:      "alpine:3.20",
			User:       "1000:1000",
			Hostname:   "app-host",
			WorkingDir: "/app",
			Cmd:        []string{"sh", "-c", "echo ORIGINAL"},
		},
		HostConfig: &container.HostConfig{
			CapAdd:            []string{"CAP_NET_ADMIN", "CAP_SYS_TIME"},
			CapDrop:           []string{"CAP_MKNOD"},
			GroupAdd:          []string{"2000", "3000"},
			Privileged:        true,
			ReadonlyRootfs:    true,
			Runtime:           "runc",
			SecurityOpt:       []string{"no-new-privileges:true"},
			Sysctls:           map[string]string{"net.ipv4.ip_forward": "1"},
			PidMode:           "host",
			IpcMode:           "host",
			CgroupnsMode:      "host",
			UsernsMode:        "keep-id",
			UTSMode:           "host",
			NetworkMode:       "demo_frontend",
			Devices:           []container.DeviceMapping{{PathOnHost: "/dev/null", PathInContainer: "/dev/null", CgroupPermissions: "rwm"}},
			DeviceCgroupRules: []string{"c 1:3 mr"},
			CgroupParent:      "/docker",
			Isolation:         "default",
			VolumesFrom:       []string{"other"},
			Links:             []string{"other:alias"},
			// Compose sends bind mounts and simple named volumes through the
			// legacy Binds list and a tmpfs entry through the Tmpfs map.
			Binds: []string{
				projectDir + "/config:/app/config:ro",
				"demo_cache:/cache:rw",
			},
			Tmpfs:        map[string]string{"/tmpmount": "size=1m,mode=1777"},
			PortBindings: map[nat.Port][]nat.PortBinding{},
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				"demo_frontend": {Aliases: []string{"demo-app-run-abc123"}},
			},
		},
	}
	return project, service, req
}

// mustAllow runs a mutation that must be permitted, even though the request then
// differs from the Compose file.
func mustAllow(t *testing.T, what string, mutate func(service *types.ServiceConfig, req *container.CreateRequest)) {
	t.Helper()
	project, service, req := fixture()
	mutate(&service, req)
	if err := compareService(project, service, req, modeCreate); err != nil {
		t.Fatalf("v1 forwards %s, so a difference there must be allowed; got: %v", what, err)
	}
}

// mustDeny runs a mutation that must be refused, and checks which field the
// refusal names, so that a refusal for an unrelated field does not pass.
func mustDeny(t *testing.T, what, wantField string, mutate func(service *types.ServiceConfig, req *container.CreateRequest)) {
	mustDenyDetail(t, what, wantField, "", mutate)
}

func mustDenyDetail(t *testing.T, what, wantField, wantDetail string, mutate func(service *types.ServiceConfig, req *container.CreateRequest)) {
	t.Helper()
	project, service, req := fixture()
	mutate(&service, req)
	err := compareService(project, service, req, modeCreate)
	if err == nil {
		t.Fatalf("v1 refuses %s, so the difference must be denied", what)
	}
	pe, ok := Inspect(err)
	if !ok {
		t.Fatalf("expected a policy error for %s, got %v", what, err)
	}
	if pe.Field != wantField {
		t.Fatalf("%s: expected a refusal on field %q, got %q (%s)", what, wantField, pe.Field, pe.Detail)
	}
	if wantDetail != "" && pe.Detail != wantDetail {
		t.Fatalf("%s: detail = %q, want %q", what, pe.Detail, wantDetail)
	}
}

func TestAllowsMatchingRequest(t *testing.T) {
	project, service, req := fixture()
	if err := compareService(project, service, req, modeCreate); err != nil {
		t.Fatalf("the fixture itself must be acceptable, got %v", err)
	}
}

// Class A, host confidentiality, integrity and isolation

func TestDeniesImageChange(t *testing.T) {
	mustDeny(t, "an undeclared image", "Config.Image", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.Config.Image = "alpine:latest"
	})
}

func TestDeniesUserChange(t *testing.T) {
	mustDeny(t, "a user override", "Config.User", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.Config.User = "root"
	})
}

func TestDeniesEntrypointChange(t *testing.T) {
	mustDeny(t, "an entrypoint override", "Config.Entrypoint", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Entrypoint = []string{"/entrypoint.sh"}
		req.Config.Entrypoint = []string{"/other.sh"}
	})
}

func TestDeniesSupplementalGroupAdded(t *testing.T) {
	mustDeny(t, "an added supplemental group", "HostConfig.GroupAdd", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.GroupAdd = []string{"2000", "3000", "0"}
	})
}

func TestDeniesPrivilegedEnabled(t *testing.T) {
	mustDeny(t, "privileged", "HostConfig.Privileged", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Privileged = false
		req.HostConfig.Privileged = true
	})
}

func TestDeniesCapabilityAdded(t *testing.T) {
	mustDeny(t, "an added capability", "HostConfig.CapAdd", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.CapAdd = append(req.HostConfig.CapAdd, "CAP_SYS_ADMIN")
	})
}

func TestDeniesDroppedCapabilityLifted(t *testing.T) {
	mustDeny(t, "a lifted capability drop", "HostConfig.CapDrop", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.CapDrop = nil
	})
}

func TestDeniesDroppedCapabilityAddedBack(t *testing.T) {
	mustDeny(t, "a dropped capability added back", "HostConfig.CapAdd", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.CapAdd = append(req.HostConfig.CapAdd, "CAP_MKNOD")
	})
}

func TestDeniesSecurityOptionRemoved(t *testing.T) {
	mustDeny(t, "a removed security option", "HostConfig.SecurityOpt", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.SecurityOpt = nil
	})
}

func TestDeniesSecurityOptionWeakened(t *testing.T) {
	mustDeny(t, "no-new-privileges turned off", "HostConfig.SecurityOpt", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.SecurityOpt = []string{"no-new-privileges:false"}
	})
}

// Compose writes the bare form for the flag, which the daemon reads as on. It has
// to compare as on too, or a request turning it off reads as an unchanged value.
func TestNoNewPrivilegesBareFormMeansOn(t *testing.T) {
	mustAllow(t, "a bare no-new-privileges against no-new-privileges:true",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.SecurityOpt = []string{"no-new-privileges"}
			req.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
		})
	mustAllow(t, "no-new-privileges:true against a bare no-new-privileges",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.SecurityOpt = []string{"no-new-privileges"}
		})
	mustDeny(t, "no-new-privileges turned off behind a bare declaration", "HostConfig.SecurityOpt",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.SecurityOpt = []string{"no-new-privileges"}
			req.HostConfig.SecurityOpt = []string{"no-new-privileges:false"}
		})
}

func TestDeniesSecurityOptionAdded(t *testing.T) {
	mustDeny(t, "an undeclared security option", "HostConfig.SecurityOpt", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.SecurityOpt = append(req.HostConfig.SecurityOpt, "seccomp=unconfined")
	})
}

func TestSeccompProfileIsNotWrittenOut(t *testing.T) {
	const secret = "S3cr3t-compose-only"
	project, service, req := fixture()
	service.SecurityOpt = []string{`seccomp={"defaultAction":"SCMP_ACT_ERRNO","note":"` + secret + `"}`}
	req.HostConfig.SecurityOpt = []string{`seccomp={"defaultAction":"SCMP_ACT_ALLOW"}`}

	err := compareService(project, service, req, modeCreate)
	pe, ok := Inspect(err)
	if !ok {
		t.Fatalf("a changed seccomp profile was accepted")
	}
	if strings.Contains(pe.Detail, secret) {
		t.Errorf("the refusal writes out %q: %q", secret, pe.Detail)
	}
	if want := `found a different seccomp profile`; !strings.Contains(pe.Detail, want) {
		t.Errorf("detail = %q, want it to mention %q", pe.Detail, want)
	}
}

func TestDeniesReadOnlyRootfsRemoved(t *testing.T) {
	mustDeny(t, "a writable root filesystem", "HostConfig.ReadonlyRootfs", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.ReadonlyRootfs = false
	})
}

func TestDeniesMaskedPathsDisabled(t *testing.T) {
	mustDeny(t, "disabled masked paths", "HostConfig.MaskedPaths", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.MaskedPaths = []string{"/proc/kcore"}
	})
}

func TestDeniesReadonlyPathsDisabled(t *testing.T) {
	mustDeny(t, "disabled read-only paths", "HostConfig.ReadonlyPaths", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.ReadonlyPaths = []string{"/proc/sys"}
	})
}

func TestDeniesRuntimeChanged(t *testing.T) {
	mustDeny(t, "a changed runtime", "HostConfig.Runtime", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Runtime = "nvidia"
	})
}

func TestDeniesRuntimeAddedWhenUndeclared(t *testing.T) {
	mustDeny(t, "a runtime compose did not declare", "HostConfig.Runtime", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Runtime = ""
		req.HostConfig.Runtime = "nvidia"
	})
}

func TestDeniesSysctlChanged(t *testing.T) {
	mustDeny(t, "a changed sysctl", "HostConfig.Sysctls", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Sysctls["net.ipv4.ip_forward"] = "0"
	})
}

func TestDeniesSysctlAdded(t *testing.T) {
	mustDeny(t, "an added sysctl", "HostConfig.Sysctls", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Sysctls["kernel.core_pattern"] = "|/tmp/x"
	})
}

func TestDeniesNamespaceChanged(t *testing.T) {
	cases := []struct {
		name   string
		field  string
		detail string
		mutate func(*container.HostConfig)
	}{
		{"pid", "HostConfig.PidMode", `compose declares "host", found "private"`,
			func(h *container.HostConfig) { h.PidMode = "private" }},
		{"ipc", "HostConfig.IpcMode", "", func(h *container.HostConfig) { h.IpcMode = "private" }},
		{"cgroup", "HostConfig.CgroupnsMode", "", func(h *container.HostConfig) { h.CgroupnsMode = "private" }},
		{"userns", "HostConfig.UsernsMode", "", func(h *container.HostConfig) { h.UsernsMode = "host" }},
		{"uts", "HostConfig.UTSMode", "", func(h *container.HostConfig) { h.UTSMode = "private" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustDenyDetail(t, "a changed "+tc.name+" namespace", tc.field, tc.detail, func(_ *types.ServiceConfig, req *container.CreateRequest) {
				tc.mutate(req.HostConfig)
			})
		})
	}
}

func TestCgroupNamespaceMustBeDeclaredExplicitly(t *testing.T) {
	mustDeny(t, "an omitted cgroup namespace against cgroup: private", "HostConfig.CgroupnsMode",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Cgroup = "private"
			req.HostConfig.CgroupnsMode = ""
		})
	mustAllow(t, "cgroup: private", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Cgroup = "private"
		req.HostConfig.CgroupnsMode = "private"
	})
}

func TestDeniesDeviceAdded(t *testing.T) {
	mustDeny(t, "an added device", "HostConfig.Devices", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Devices = append(req.HostConfig.Devices, container.DeviceMapping{
			PathOnHost: "/dev/sda", PathInContainer: "/dev/sda", CgroupPermissions: "rwm",
		})
	})
}

func TestDeniesDeviceRequestAdded(t *testing.T) {
	mustDeny(t, "an added device request", "HostConfig.DeviceRequests", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.DeviceRequests = []container.DeviceRequest{{
			Driver: "nvidia", Count: -1, Capabilities: [][]string{{"gpu"}},
		}}
	})
}

// A driver option is a value, so two option maps that only look alike once written
// out must stay apart.
func TestDeniesDeviceRequestOptionsCollision(t *testing.T) {
	mustDeny(t, "device request options that collide when written out", "HostConfig.DeviceRequests",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Gpus = []types.DeviceRequest{{Driver: "nvidia", Options: types.Mapping{"a": "1", "b": "2"}}}
			req.HostConfig.DeviceRequests = []container.DeviceRequest{{
				Driver:       "nvidia",
				Capabilities: [][]string{{"gpu"}},
				Options:      map[string]string{"a": "1 opt:b=2"},
			}}
		})
}

func TestAllowsDeviceRequestOptionsInAnyOrder(t *testing.T) {
	mustAllow(t, "device request options written in another order", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Gpus = []types.DeviceRequest{{Driver: "nvidia", Options: types.Mapping{"a": "1", "b": "2"}}}
		req.HostConfig.DeviceRequests = []container.DeviceRequest{{
			Driver:       "nvidia",
			Capabilities: [][]string{{"gpu"}},
			Options:      map[string]string{"b": "2", "a": "1"},
		}}
	})
}

func TestDeniesDeviceCgroupRuleAdded(t *testing.T) {
	mustDeny(t, "an added device cgroup rule", "HostConfig.DeviceCgroupRules", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.DeviceCgroupRules = append(req.HostConfig.DeviceCgroupRules, "a *:* rwm")
	})
}

func TestDeniesVolumesFromAdded(t *testing.T) {
	mustDeny(t, "volumes_from another container", "HostConfig.VolumesFrom", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.VolumesFrom = []string{"other", "a-victim"}
	})
}

func TestDeniesCgroupParentChanged(t *testing.T) {
	mustDeny(t, "a changed cgroup parent", "HostConfig.CgroupParent", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.CgroupParent = "/somebody-elses-cgroup"
	})
}

func TestDeniesIsolationChanged(t *testing.T) {
	mustDeny(t, "a changed isolation technology", "HostConfig.Isolation", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Isolation = "hyperv"
	})
}

func TestDeniesContainerIDFile(t *testing.T) {
	mustDeny(t, "a container id file on a host path", "HostConfig.ContainerIDFile", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.ContainerIDFile = "/tmp/id"
	})
}

func TestDeniesCgroupSelector(t *testing.T) {
	mustDeny(t, "a direct cgroup selector", "HostConfig.Cgroup", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Cgroup = "container:abc"
	})
}

func TestDeniesBindMountAdded(t *testing.T) {
	mustDeny(t, "an added bind mount", "HostConfig.Binds", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Binds = append(req.HostConfig.Binds, "/:/host:rw")
	})
}

func TestDeniesBindSourceChanged(t *testing.T) {
	mustDeny(t, "a changed bind source", "HostConfig.Binds", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Binds[0] = "/etc:/app/config:ro"
	})
}

func TestDeniesBindTargetChanged(t *testing.T) {
	mustDeny(t, "a changed bind target", "HostConfig.Binds", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Binds[0] = projectDir + "/config:/app/other:ro"
	})
}

func TestDeniesReadOnlyMountMadeWritable(t *testing.T) {
	mustDeny(t, "a read-only mount made writable", "HostConfig.Binds", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Binds[0] = projectDir + "/config:/app/config:rw"
	})
}

func TestDeniesNamedVolumeChanged(t *testing.T) {
	mustDeny(t, "a different named volume", "HostConfig.Binds", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Binds[1] = "someone_else:/cache:rw"
	})
}

func TestDeniesMountDropped(t *testing.T) {
	mustDeny(t, "a dropped mount", "HostConfig", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Binds = req.HostConfig.Binds[1:]
	})
}

func TestDeniesTmpfsPathAdded(t *testing.T) {
	mustDeny(t, "an added tmpfs", "HostConfig.Tmpfs", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Tmpfs["/extra"] = "size=1m"
	})
}

func TestDeniesTmpfsMadeWritable(t *testing.T) {
	mustDeny(t, "a writable tmpfs", "HostConfig.Tmpfs", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Tmpfs = types.StringList{"/tmpmount:size=1m,mode=1777,ro"}
		req.HostConfig.Tmpfs["/tmpmount"] = "size=1m,mode=1777"
	})
}

func TestDeniesLegacyConfigVolumes(t *testing.T) {
	mustDeny(t, "the legacy Config.Volumes map", "Config.Volumes", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.Config.Volumes = map[string]struct{}{"/data": {}}
	})
}

func TestDeniesUnresolvableDeclaredMounts(t *testing.T) {
	cases := []struct {
		name    string
		field   string
		project func(*types.Project)
		service func(*types.ServiceConfig)
	}{
		{"a secret at a mounted path", "volumes", func(p *types.Project) {
			p.Secrets = types.Secrets{"token": {File: projectDir + "/token"}}
		}, func(s *types.ServiceConfig) {
			s.Secrets = []types.ServiceSecretConfig{{Source: "token", Target: "/app/config"}}
		}},
		{"a config at a mounted path", "volumes", func(p *types.Project) {
			p.Configs = types.Configs{"settings": {File: projectDir + "/settings"}}
		}, func(s *types.ServiceConfig) {
			s.Configs = []types.ServiceConfigObjConfig{{Source: "settings", Target: "/app/config"}}
		}},
		{"a secret the project does not declare", "secrets", func(*types.Project) {}, func(s *types.ServiceConfig) {
			s.Secrets = []types.ServiceSecretConfig{{Source: "not-declared"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project, service, req := fixture()
			tc.project(project)
			tc.service(&service)

			err := compareService(project, service, req, modeCreate)
			pe, ok := Inspect(err)
			if !ok || pe.Field != tc.field {
				t.Fatalf("a mount compose cannot resolve must be refused on %s, got %v", tc.field, err)
			}
			if pe.Service != "app" {
				t.Errorf("the refusal must name the service that declared the mount, got %q", pe.Service)
			}
		})
	}
}

// TestAllowsEquivalentMountSerialisations is the representation-independence
// guarantee. The same mount in any representation Compose may use canonicalises alike.
func TestAllowsEquivalentMountSerialisations(t *testing.T) {
	// Docker Compose uses the Mount API when a bind needs propagation.
	mustAllow(t, "a propagated bind sent through the Mount API",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[0].Bind.Propagation = "rslave"
			req.HostConfig.Binds = req.HostConfig.Binds[1:]
			req.HostConfig.Mounts = []mount.Mount{{
				Type:     mount.TypeBind,
				Source:   projectDir + "/config",
				Target:   "/app/config",
				ReadOnly: true,
				BindOptions: &mount.BindOptions{
					Propagation:      "rslave",
					CreateMountpoint: true,
				},
			}}
		})

	// Docker Compose uses the Mount API when a volume needs nocopy.
	mustAllow(t, "a nocopy volume sent through the Mount API",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[1].Volume = &types.ServiceVolumeVolume{NoCopy: true}
			req.HostConfig.Binds = req.HostConfig.Binds[:1]
			req.HostConfig.Mounts = []mount.Mount{{
				Type:          mount.TypeVolume,
				Source:        "demo_cache",
				Target:        "/cache",
				VolumeOptions: &mount.VolumeOptions{NoCopy: true},
			}}
		})

	// A bind Compose would express as a bind string is equally acceptable through
	// the Mount API, as long as it says the same thing.
	mustAllow(t, "a plain bind sent through the Mount API",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[0].Bind.Propagation = ""
			req.HostConfig.Binds = req.HostConfig.Binds[1:]
			req.HostConfig.Mounts = []mount.Mount{mountBind(projectDir+"/config", "/app/config", true)}
		})

	// A tmpfs is expressed through HostConfig.Tmpfs rather than Mounts.
	mustAllow(t, "a tmpfs expressed through the Mount API",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.Tmpfs = nil
			req.HostConfig.Mounts = append(req.HostConfig.Mounts, mount.Mount{
				Type:         mount.TypeTmpfs,
				Target:       "/tmpmount",
				TmpfsOptions: &mount.TmpfsOptions{SizeBytes: 1 << 20, Mode: 0o1777},
			})
		})
}

func TestDeniesMountOptionsThatChangeHostAccess(t *testing.T) {
	cases := []struct {
		name   string
		field  string
		detail string
		mutate func(*types.ServiceConfig, *container.CreateRequest)
	}{
		{"create_host_path turned off", "HostConfig.Mounts", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			// The Mount API form carries the flag. The bind string form always
			// creates the path, so only the explicit form can turn it off.
			i := swapBindToMount(req)
			req.HostConfig.Mounts[i].BindOptions.CreateMountpoint = false
		}},
		{"create_host_path turned on", "HostConfig.Mounts", "", func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[0].Bind.CreateHostPath = false
			i := swapBindToMount(req)
			req.HostConfig.Mounts[i].BindOptions.CreateMountpoint = true
		}},
		{"volume subpath changed", "HostConfig.Mounts", "", func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[1].Volume = &types.ServiceVolumeVolume{Subpath: "restricted"}
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.Subpath = "other"
		}},
		{"volume subpath dropped", "HostConfig.Mounts", "", func(s *types.ServiceConfig, req *container.CreateRequest) {
			// Declaring a subpath is a constraint, dropping it widens what the
			// container can read.
			s.Volumes[1].Volume = &types.ServiceVolumeVolume{Subpath: "restricted"}
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.Subpath = ""
		}},
		{"nocopy turned on", "HostConfig.Mounts", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.NoCopy = true
		}},
		{"nocopy turned off", "HostConfig.Mounts", "", func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[1].Volume = &types.ServiceVolumeVolume{NoCopy: true}
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.NoCopy = false
		}},
		{"SELinux relabelling added", "HostConfig.Binds", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.Binds[0] = projectDir + "/config:/app/config:ro,z"
		}},
		{"SELinux relabelling changed", "HostConfig.Binds", "", func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[0].Bind.SELinux = "z"
			req.HostConfig.Binds[0] = projectDir + "/config:/app/config:ro,Z"
		}},
		{"non-recursive binding turned on", "HostConfig.Mounts", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			i := swapBindToMount(req)
			req.HostConfig.Mounts[i].BindOptions.NonRecursive = true
		}},
		{"writable non-recursive binding turned on", "HostConfig.Mounts",
			`container path "/app/config": ReadOnlyNonRecursive differs (compose: false, found: true)`,
			func(_ *types.ServiceConfig, req *container.CreateRequest) {
				i := swapBindToMount(req)
				req.HostConfig.Mounts[i].BindOptions.ReadOnlyNonRecursive = true
			}},
		{"forced read-only recursion turned off", "HostConfig.Mounts", "", func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[0].Bind.Recursive = "readonly"
			i := swapBindToMount(req)
			req.HostConfig.Mounts[i].BindOptions.ReadOnlyForceRecursive = false
		}},
		{"per-mount volume driver added", "HostConfig.Mounts", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.DriverConfig = &mount.Driver{Name: "nfs"}
		}},
		{"per-mount volume driver options added", "HostConfig.Mounts", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.DriverConfig = &mount.Driver{
				Name: "local", Options: map[string]string{"type": "nfs"},
			}
		}},
		{"volume labels added", "HostConfig.Mounts", "", func(_ *types.ServiceConfig, req *container.CreateRequest) {
			i := swapVolumeToMount(req)
			req.HostConfig.Mounts[i].VolumeOptions.Labels = map[string]string{"attacker": "controlled"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustDenyDetail(t, tc.name, tc.field, tc.detail, tc.mutate)
		})
	}
}

func TestDeniesBindPropagationChanged(t *testing.T) {
	mustDeny(t, "bind propagation compose did not declare", "HostConfig.Binds",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Volumes[0].Bind.Propagation = ""
			req.HostConfig.Binds[0] = projectDir + "/config:/app/config:ro,rshared"
		})
	mustAllow(t, "the declared propagation", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Volumes[0].Bind.Propagation = "rslave"
		req.HostConfig.Binds[0] = projectDir + "/config:/app/config:ro,rslave"
	})
}

func imageProject(subpath string) (*types.Project, types.ServiceConfig, *container.CreateRequest) {
	project, _, _ := fixture()
	project.Services = nil
	project.Networks = nil

	service := types.ServiceConfig{
		Name:  "app",
		Image: "alpine:3.20",
		Volumes: []types.ServiceVolumeConfig{{
			Type:   types.VolumeTypeImage,
			Source: "alpine:3.20",
			Target: "/img",
			Image:  &types.ServiceVolumeImage{SubPath: subpath},
		}},
	}
	req := &container.CreateRequest{
		Config:     &container.Config{Image: "alpine:3.20"},
		HostConfig: &container.HostConfig{NetworkMode: "none"},
	}
	return project, service, req
}

func TestImageMount(t *testing.T) {
	t.Run("matching source and subpath", func(t *testing.T) {
		project, service, req := imageProject("usr/share")
		req.HostConfig.Mounts = []mount.Mount{{
			Type:         mount.TypeImage,
			Source:       "alpine:3.20",
			Target:       "/img",
			ImageOptions: &mount.ImageOptions{Subpath: "usr/share"},
		}}
		if err := compareService(project, service, req, modeCreate); err != nil {
			t.Fatalf("a matching image mount must be accepted, got %v", err)
		}
	})

	t.Run("different source", func(t *testing.T) {
		project, service, req := imageProject("usr/share")
		req.HostConfig.Mounts = []mount.Mount{{
			Type:         mount.TypeImage,
			Source:       "evil:latest",
			Target:       "/img",
			ImageOptions: &mount.ImageOptions{Subpath: "usr/share"},
		}}
		err := compareService(project, service, req, modeCreate)
		if pe, ok := Inspect(err); !ok || pe.Field != "HostConfig.Mounts" {
			t.Fatalf("a different image source must be refused, got %v", err)
		}
	})

	t.Run("subpath changed", func(t *testing.T) {
		project, service, req := imageProject("usr/share")
		req.HostConfig.Mounts = []mount.Mount{{
			Type:         mount.TypeImage,
			Source:       "alpine:3.20",
			Target:       "/img",
			ImageOptions: &mount.ImageOptions{Subpath: "etc"},
		}}
		if err := compareService(project, service, req, modeCreate); err == nil {
			t.Fatal("a changed image subpath must be refused")
		}
	})

	t.Run("subpath removed", func(t *testing.T) {
		project, service, req := imageProject("usr/share")
		req.HostConfig.Mounts = []mount.Mount{{
			Type:   mount.TypeImage,
			Source: "alpine:3.20",
			Target: "/img",
		}}
		if err := compareService(project, service, req, modeCreate); err == nil {
			t.Fatal("dropping the image subpath widens what the container sees and must be refused")
		}
	})
}

func TestAnnotations(t *testing.T) {
	t.Run("matching", func(t *testing.T) {
		mustAllow(t, "matching annotations", func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Annotations = types.Mapping{"org.example": "value"}
			req.HostConfig.Annotations = map[string]string{"org.example": "value"}
		})
	})
	t.Run("extra annotation", func(t *testing.T) {
		mustDeny(t, "an undeclared annotation", "HostConfig.Annotations",
			func(_ *types.ServiceConfig, req *container.CreateRequest) {
				req.HostConfig.Annotations = map[string]string{"org.example.attacker": "value"}
			})
	})
	t.Run("changed value", func(t *testing.T) {
		mustDeny(t, "a changed annotation", "HostConfig.Annotations",
			func(s *types.ServiceConfig, req *container.CreateRequest) {
				s.Annotations = types.Mapping{"org.example": "value"}
				req.HostConfig.Annotations = map[string]string{"org.example": "other"}
			})
	})
}

// swapBindToMount re-expresses the first bind mount through the Mount API, the only
// representation that can carry the bind options under test.
func swapBindToMount(req *container.CreateRequest) int {
	req.HostConfig.Binds = req.HostConfig.Binds[1:]
	req.HostConfig.Mounts = append(req.HostConfig.Mounts, mountBind(projectDir+"/config", "/app/config", true))
	return len(req.HostConfig.Mounts) - 1
}

// swapVolumeToMount re-expresses the named volume through the Mount API, where the
// volume options live.
func swapVolumeToMount(req *container.CreateRequest) int {
	req.HostConfig.Binds = req.HostConfig.Binds[:1]
	req.HostConfig.Mounts = append(req.HostConfig.Mounts, mount.Mount{
		Type:          mount.TypeVolume,
		Source:        "demo_cache",
		Target:        "/cache",
		VolumeOptions: &mount.VolumeOptions{},
	})
	return len(req.HostConfig.Mounts) - 1
}

// Class B, Docker specific network exposure

func TestDeniesHostNetworkMode(t *testing.T) {
	mustDeny(t, "host networking", "HostConfig.NetworkMode", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Networks = nil
		req.HostConfig.NetworkMode = "host"
		req.NetworkingConfig.EndpointsConfig = map[string]*network.EndpointSettings{}
	})
}

func TestDeniesJoiningAnotherContainerNamespace(t *testing.T) {
	mustDeny(t, "joining another container's network namespace", "HostConfig.NetworkMode",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Networks = nil
			req.HostConfig.NetworkMode = "container:victim"
			req.NetworkingConfig.EndpointsConfig = map[string]*network.EndpointSettings{}
		})
}

func TestDeniesNetworkAttached(t *testing.T) {
	mustDeny(t, "an undeclared network attachment", "NetworkingConfig.EndpointsConfig",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.NetworkingConfig.EndpointsConfig["demo_extra"] = &network.EndpointSettings{}
		})
}

func TestDeniesNetworkMissing(t *testing.T) {
	mustDeny(t, "a dropped network attachment", "NetworkingConfig.EndpointsConfig",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.NetworkingConfig.EndpointsConfig = map[string]*network.EndpointSettings{}
		})
}

func TestDeniesNetworkReplaced(t *testing.T) {
	mustDeny(t, "another network instead of the declared one", "HostConfig.NetworkMode",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.NetworkMode = "demo_elsewhere"
		})
}

func TestDeniesNetworkingTurnedOff(t *testing.T) {
	mustDeny(t, "networking turned off", "Config.NetworkDisabled", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.Config.NetworkDisabled = true
	})
}

func TestDeniesPublishAllPorts(t *testing.T) {
	mustDeny(t, "publishing all ports", "HostConfig.PublishAllPorts", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.PublishAllPorts = true
	})
}

func TestDeniesUndeclaredPortBound(t *testing.T) {
	mustDeny(t, "an undeclared host port bound", "HostConfig.PortBindings",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.PortBindings = map[nat.Port][]nat.PortBinding{
				"80/tcp":  {{HostPort: "8080"}},
				"90/udp":  {{HostIP: "127.0.0.1", HostPort: "9090"}},
				"443/tcp": {{HostPort: "8443"}},
			}
		})
}

func TestDeniesHostPortChanged(t *testing.T) {
	mustDeny(t, "a changed host port", "HostConfig.PortBindings", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.PortBindings = map[nat.Port][]nat.PortBinding{
			"80/tcp": {{HostPort: "1234"}},
			"90/udp": {{HostIP: "127.0.0.1", HostPort: "9090"}},
		}
	})
}

func TestDeniesHostIPChanged(t *testing.T) {
	mustDeny(t, "a changed host address", "HostConfig.PortBindings", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.PortBindings = map[nat.Port][]nat.PortBinding{
			"80/tcp": {{HostPort: "8080"}},
			"90/udp": {{HostIP: "0.0.0.0", HostPort: "9090"}},
		}
	})
}

func TestAllowsDeclaredServicePorts(t *testing.T) {
	mustAllow(t, "the service's own ports, as --service-ports publishes them",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.PortBindings = map[nat.Port][]nat.PortBinding{
				"80/tcp": {{HostPort: "8080"}},
				"90/udp": {{HostIP: "127.0.0.1", HostPort: "9090"}},
			}
			req.Config.ExposedPorts = nat.PortSet{"80/tcp": {}, "90/udp": {}}
		})
}

func TestPortBindingsMustMatchExactly(t *testing.T) {
	cases := []struct {
		name     string
		bindings []nat.PortBinding
		allowed  bool
	}{
		{"the declared bindings in another order", []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: "8081"},
			{HostIP: "127.0.0.1", HostPort: "8080"},
		}, true},
		{"the declared bindings", []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: "8080"},
			{HostIP: "127.0.0.1", HostPort: "8081"},
		}, true},
		{"one declared binding repeated", []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: "8080"},
			{HostIP: "127.0.0.1", HostPort: "8080"},
		}, false},
		{"one declared binding dropped", []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: "8080"},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutate := func(s *types.ServiceConfig, req *container.CreateRequest) {
				s.Ports = []types.ServicePortConfig{
					{Target: 80, Published: "8080", Protocol: "tcp", HostIP: "127.0.0.1"},
					{Target: 80, Published: "8081", Protocol: "tcp", HostIP: "127.0.0.1"},
				}
				req.HostConfig.PortBindings = map[nat.Port][]nat.PortBinding{"80/tcp": tc.bindings}
			}
			if tc.allowed {
				mustAllow(t, tc.name, mutate)
				return
			}
			mustDeny(t, tc.name, "HostConfig.PortBindings", mutate)
		})
	}
}

func TestMatchCreateTriesEveryService(t *testing.T) {
	project, service, req := fixture()

	// The request's own Compose labels name no service, so a match can only come
	// from comparing every service in the project.
	project.Services = types.Services{
		"other": {Name: "other", Image: "busybox", User: "1000:1000"},
		"app":   service,
	}
	req.Config.Labels = map[string]string{
		LabelProject: projectName,
		LabelService: "does-not-exist",
	}
	matched, err := (&Policy{project: project}).matchCreate(req)
	if err != nil {
		t.Fatalf("expected a match, got %v", err)
	}
	if matched != "app" {
		t.Fatalf("expected the request to match service %q, got %q", "app", matched)
	}
}

func TestUnmatchedCreateNamesAComparableService(t *testing.T) {
	_, app, _ := fixture()
	other := types.ServiceConfig{Name: "other", Image: "busybox", User: "1000:1000"}
	mirror := types.ServiceConfig{Name: "mirror", Image: "alpine:3.20", User: "2000:2000"}

	cases := []struct {
		name     string
		services types.Services
		prepare  func(*container.CreateRequest)
		want     string
	}{
		{
			name:     "an image no service declares",
			services: types.Services{"other": other, "app": app},
			prepare:  func(r *container.CreateRequest) { r.Config.Labels, r.Config.Image = nil, "evil:latest" },
			want:     `no Compose service matches image "evil:latest"`,
		},
		{
			name:     "the service the label names",
			services: types.Services{"other": other, "app": app},
			prepare: func(r *container.CreateRequest) {
				r.Config.Labels, r.Config.User = map[string]string{LabelService: "app"}, "root"
			},
			want: `service "app": Config.User: compose declares "1000:1000", found "root"`,
		},
		{
			name:     "the only service using the image",
			services: types.Services{"other": other, "app": app},
			prepare:  func(r *container.CreateRequest) { r.Config.Labels, r.Config.User = nil, "root" },
			want:     `service "app": Config.User: compose declares "1000:1000", found "root"`,
		},
		{
			name:     "several services using the image",
			services: types.Services{"app": app, "mirror": mirror},
			prepare:  func(r *container.CreateRequest) { r.Config.Labels, r.Config.User = nil, "root" },
			want:     "no Compose service matches this request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project, _, req := fixture()
			project.Services = tc.services
			tc.prepare(req)

			_, err := (&Policy{project: project}).matchCreate(req)
			if err == nil {
				t.Fatal("a request matching no service was accepted")
			}
			if err.Error() != tc.want {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestMalformedBindNamesTheFieldOnce(t *testing.T) {
	project, service, req := fixture()
	req.HostConfig.Binds = append(req.HostConfig.Binds, "no-container-path")

	err := compareService(project, service, req, modeCreate)
	if err == nil {
		t.Fatal("a bind entry without a container path was accepted")
	}
	if got := strings.Count(err.Error(), "HostConfig.Binds"); got != 1 {
		t.Fatalf("the field is named %d times in %q", got, err)
	}
}

// TestRejectsIncompleteRequest guards the fail-closed default. A request missing
// its Config or HostConfig is refused rather than read as unrestricted.
func TestRejectsIncompleteRequest(t *testing.T) {
	project, service, req := fixture()

	if err := compareService(project, service, &container.CreateRequest{Config: req.Config}, modeCreate); err == nil {
		t.Error("a create request without a HostConfig was accepted")
	}
	if err := compareService(project, service, &container.CreateRequest{HostConfig: req.HostConfig}, modeCreate); err == nil {
		t.Error("a create request without a Config was accepted")
	}
	if err := compareService(project, service, nil, modeCreate); err == nil {
		t.Error("a nil create request was accepted")
	}
}
