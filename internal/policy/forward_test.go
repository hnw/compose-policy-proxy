package policy

import (
	"testing"
	"time"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

// Each test asserts that a request differing from the Compose file in exactly one
// field is allowed, so losing a comparison shows up as a denial.

// mountBind builds the Mount API form of a bind mount. CreateMountpoint makes it
// equivalent to the legacy bind string, which always creates the host path.
func mountBind(source, target string, readOnly bool) mount.Mount {
	return mount.Mount{
		Type:     mount.TypeBind,
		Source:   source,
		Target:   target,
		ReadOnly: readOnly,
		BindOptions: &mount.BindOptions{
			CreateMountpoint: true,
		},
	}
}

// Class C, availability and resource consumption

func TestForwardsResourceLimits(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*container.HostConfig)
	}{
		{"memory limit", func(h *container.HostConfig) { h.Memory = 64 << 30 }},
		{"memory reservation", func(h *container.HostConfig) { h.MemoryReservation = 32 << 30 }},
		{"memory swap", func(h *container.HostConfig) { h.MemorySwap = -1 }},
		{"memory swappiness", func(h *container.HostConfig) { v := int64(0); h.MemorySwappiness = &v }},
		{"cpu shares", func(h *container.HostConfig) { h.CPUShares = 4096 }},
		{"cpu quota", func(h *container.HostConfig) { h.CPUQuota = 500000 }},
		{"cpu period", func(h *container.HostConfig) { h.CPUPeriod = 50000 }},
		{"nano cpus", func(h *container.HostConfig) { h.NanoCPUs = 4e9 }},
		{"cpuset", func(h *container.HostConfig) { h.CpusetCpus = "0-3" }},
		{"cpuset memory", func(h *container.HostConfig) { h.CpusetMems = "0" }},
		{"shared memory size", func(h *container.HostConfig) { h.ShmSize = 512 << 20 }},
		{"oom score adj", func(h *container.HostConfig) { h.OomScoreAdj = -1000 }},
		{"oom kill disable", func(h *container.HostConfig) { v := true; h.OomKillDisable = &v }},
		{"pids limit", func(h *container.HostConfig) { v := int64(1 << 20); h.PidsLimit = &v }},
		{"ulimits", func(h *container.HostConfig) {
			h.Ulimits = []*container.Ulimit{{Name: "nofile", Soft: 1 << 20, Hard: 1 << 20}}
		}},
		{"blkio weight", func(h *container.HostConfig) { h.BlkioWeight = 1000 }},
		{"console size", func(h *container.HostConfig) { h.ConsoleSize = [2]uint{1000, 1000} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustAllow(t, tc.name, func(_ *types.ServiceConfig, req *container.CreateRequest) {
				tc.mutate(req.HostConfig)
			})
		})
	}
}

// TestForwardsLogConfig pins that the logging driver is forwarded. The rationale
// is recorded against LogConfig in the classification table.
func TestForwardsLogConfig(t *testing.T) {
	mustAllow(t, "an arbitrary log driver", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.LogConfig = container.LogConfig{
			Type:   "syslog",
			Config: map[string]string{"syslog-address": "tcp://198.51.100.7:514"},
		}
	})
}

// Class D, container internals and general network behaviour

func TestForwardsContainerInternals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*container.Config)
	}{
		{"command", func(c *container.Config) { c.Cmd = []string{"sh", "-c", "something else"} }},
		{"environment", func(c *container.Config) { c.Env = []string{"A=1", "B=2"} }},
		{"stdin", func(c *container.Config) { c.OpenStdin = true; c.StdinOnce = true }},
		{"attach", func(c *container.Config) { c.AttachStdin = true; c.AttachStdout = false }},
		{"hostname", func(c *container.Config) { c.Hostname = "attacker-chosen" }},
		{"domain name", func(c *container.Config) { c.Domainname = "attacker.test" }},
		{"working directory", func(c *container.Config) { c.WorkingDir = "/host" }},
		{"healthcheck", func(c *container.Config) {
			c.Healthcheck = &container.HealthConfig{Test: []string{"CMD-SHELL", "curl evil.test"}}
		}},
		{"stop signal", func(c *container.Config) { c.StopSignal = "SIGKILL" }},
		{"stop timeout", func(c *container.Config) { v := 3600; c.StopTimeout = &v }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustAllow(t, tc.name, func(_ *types.ServiceConfig, req *container.CreateRequest) {
				tc.mutate(req.Config)
			})
		})
	}
}

func TestForwardsInit(t *testing.T) {
	mustAllow(t, "an arbitrary init flag", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		v := true
		req.HostConfig.Init = &v
	})
}

// A terminal is the client's to choose. `docker compose run -T` turns off the one
// the Compose file asked for, and neither direction decides anything the policy confines.
func TestForwardsTTYInBothDirections(t *testing.T) {
	mustAllow(t, "a terminal the compose file asked for, turned off",
		func(s *types.ServiceConfig, req *container.CreateRequest) {
			s.Tty = true
			req.Config.Tty = false
		})
	mustAllow(t, "a terminal the compose file did not ask for",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.Config.Tty = true
		})
}

func TestForwardsRestartPolicy(t *testing.T) {
	mustAllow(t, "a restart policy", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.RestartPolicy = container.RestartPolicy{Name: "always"}
	})
}

func TestForwardsNetworkBehaviour(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*container.CreateRequest)
	}{
		{"dns servers", func(r *container.CreateRequest) { r.HostConfig.DNS = []string{"198.51.100.53"} }},
		{"dns search", func(r *container.CreateRequest) { r.HostConfig.DNSSearch = []string{"attacker.test"} }},
		{"dns options", func(r *container.CreateRequest) { r.HostConfig.DNSOptions = []string{"attacker"} }},
		{"extra hosts", func(r *container.CreateRequest) {
			r.HostConfig.ExtraHosts = []string{"metadata.google.internal:169.254.169.254"}
		}},
		{"network aliases", func(r *container.CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["demo_frontend"].Aliases = []string{"someone-elses-service"}
		}},
		{"static ip", func(r *container.CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["demo_frontend"].IPAMConfig =
				&network.EndpointIPAMConfig{IPv4Address: "172.30.0.99", IPv6Address: "fd00::99"}
		}},
		{"mac address", func(r *container.CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["demo_frontend"].MacAddress = "02:42:ac:1e:00:0b"
		}},
		{"endpoint driver options", func(r *container.CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["demo_frontend"].DriverOpts = map[string]string{"x": "y"}
		}},
		{"gateway priority", func(r *container.CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["demo_frontend"].GwPriority = 1000
		}},
		{"link-local addresses", func(r *container.CreateRequest) {
			r.NetworkingConfig.EndpointsConfig["demo_frontend"].IPAMConfig =
				&network.EndpointIPAMConfig{LinkLocalIPs: []string{"169.254.1.1"}}
		}},
		{"container-wide mac", func(r *container.CreateRequest) { r.Config.MacAddress = "02:42:ac:1e:00:0a" }},
		{"shell", func(r *container.CreateRequest) { r.Config.Shell = []string{"/bin/bash"} }},
		{"links", func(r *container.CreateRequest) {
			// A link is a name, not a route. The daemon ignores it on a
			// user-defined network, and the bridge reaches the target by IP anyway.
			r.HostConfig.Links = []string{"a-victim:alias"}
		}},
		{"exposed ports", func(r *container.CreateRequest) {
			// An exposed port with no binding produces no host listener.
			r.Config.ExposedPorts = nat.PortSet{"443/tcp": {}}
		}},
		{"onbuild triggers", func(r *container.CreateRequest) {
			// They run only during a build or a commit, neither of which is
			// reachable through this proxy.
			r.Config.OnBuild = []string{"RUN rm -rf /"}
		}},
		{"args escaped", func(r *container.CreateRequest) { r.Config.ArgsEscaped = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustAllow(t, tc.name, func(_ *types.ServiceConfig, req *container.CreateRequest) {
				tc.mutate(req)
			})
		})
	}
}

// TestForwardsMountOptions pins the mount options the policy does not compare.
func TestForwardsMountOptions(t *testing.T) {
	mustAllow(t, "a different tmpfs size", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Tmpfs["/tmpmount"] = "size=64m,mode=1777"
	})
	mustAllow(t, "a different tmpfs mode", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Tmpfs["/tmpmount"] = "size=1m,mode=0777"
	})
	mustAllow(t, "a tmpfs option the policy ignores", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.Tmpfs["/tmpmount"] = "size=1m,mode=1777,nr_inodes=1024"
	})
	mustAllow(t, "a mount consistency", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		// Consistency is how a bind behaves under fsync and grants no access.
		i := swapBindToMount(req)
		req.HostConfig.Mounts[i].Consistency = mount.ConsistencyCached
	})
}

// TestDeniesClassEStorageFields names the HostConfig fields the proxy refuses to
// reason about, spelled out so the refusal is a decision rather than an omission.
func TestDeniesClassEStorageFields(t *testing.T) {
	mustDeny(t, "a different volume driver", "HostConfig.VolumeDriver",
		func(_ *types.ServiceConfig, req *container.CreateRequest) { req.HostConfig.VolumeDriver = "nfs" })
	mustDeny(t, "different storage options", "HostConfig.StorageOpt",
		func(_ *types.ServiceConfig, req *container.CreateRequest) {
			req.HostConfig.StorageOpt = map[string]string{"size": "1T"}
		})
}

func TestForwardsCompareEquivalentValues(t *testing.T) {
	mustAllow(t, "a differently spelled capability list", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.CapAdd = []string{"CAP_SYS_TIME", "cap_net_admin"}
		req.HostConfig.CapDrop = []string{"cap_mknod"}
	})
	mustAllow(t, "reordered supplemental groups", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.GroupAdd = []string{"3000", "2000"}
	})
	mustAllow(t, "an extra capability drop", func(_ *types.ServiceConfig, req *container.CreateRequest) {
		req.HostConfig.CapDrop = []string{"CAP_MKNOD", "CAP_CHOWN"}
	})
	mustAllow(t, "a relative bind source resolved the same way", func(s *types.ServiceConfig, req *container.CreateRequest) {
		s.Volumes[0].Source = "./config"
	})
}

// TestStopGracePeriodAndForwardedFieldsTogether guards a regression where
// stop_grace_period was compared as if it were seconds.
func TestStopGracePeriodAndForwardedFieldsTogether(t *testing.T) {
	project, service, req := fixture()
	grace := types.Duration(5 * time.Second)
	service.StopGracePeriod = &grace
	req.Config.StopTimeout = intPtr(5)
	if err := compareService(project, service, req, modeCreate); err != nil {
		t.Fatalf("stop_grace_period is class D and must be forwarded, got %v", err)
	}
}

func intPtr(v int) *int { return &v }
