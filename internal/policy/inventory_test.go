package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

// Refusing to decode an unknown field makes a new Moby field fail closed. The gap
// left is a known field the policy never examined, so every field is classified below.

type fieldClass string

const (
	// classCompared:  checked against the resolved Compose project.
	classCompared fieldClass = "compared"
	// classRefused:   refused outright.
	classRefused fieldClass = "refused"
	// classForwarded: forwarded without inspection, because it cannot change host
	// confidentiality, host integrity or an isolation boundary.
	classForwarded fieldClass = "forwarded"
)

// fieldDecision records a classification and, more importantly, why.
type fieldDecision struct {
	class  fieldClass
	reason string
}

func compared(reason string) fieldDecision  { return fieldDecision{classCompared, reason} }
func refused(reason string) fieldDecision   { return fieldDecision{classRefused, reason} }
func forwarded(reason string) fieldDecision { return fieldDecision{classForwarded, reason} }

// hostConfigFields classifies container.HostConfig. Fields in the embedded
// container.Resources are classified in resourcesFields, so each is in one place.
var hostConfigFields = map[string]fieldDecision{
	// class A, identity, privilege and isolation
	"CapAdd":         compared("kernel capability added to the container"),
	"CapDrop":        compared("kernel capability restored to the container"),
	"Privileged":     compared("removes essentially every isolation boundary"),
	"ReadonlyRootfs": compared("whether the root filesystem is writable"),
	"Runtime":        compared("selects the host-side runtime that executes the container"),
	"Sysctls":        compared("namespaced kernel parameters"),
	"PidMode":        compared("host PID namespace"),
	"IpcMode":        compared("host IPC namespace"),
	"CgroupnsMode":   compared("cgroup namespace"),
	"UsernsMode":     compared("user namespace"),
	"UTSMode":        compared("UTS namespace"),
	"GroupAdd":       compared("supplemental groups, which reach the host group database"),
	"VolumesFrom":    compared("another container's volumes"),
	"Isolation":      compared("which hypervisor boundary applies"),
	"SecurityOpt":    compared("seccomp, AppArmor, SELinux and no-new-privileges"),
	"NetworkMode":    compared("host networking, or another container's network namespace"),
	"Mounts":         compared("mount entries"),
	"Binds":          compared("mount entries, legacy representation"),
	"Tmpfs":          compared("a mount; only its read-only flag is decided on"),

	// class A, refused because a value would weaken a daemon default
	"MaskedPaths":     refused("a value removes the daemon's filesystem confinement"),
	"ReadonlyPaths":   refused("a value removes the daemon's filesystem confinement"),
	"Cgroup":          refused("names a cgroup directly, which the proxy cannot resolve"),
	"ContainerIDFile": refused("names a host path for the daemon to write to"),

	// class B, Docker specific network exposure
	"PortBindings":    compared("creates host listeners"),
	"PublishAllPorts": refused("creates host listeners the Compose file never described"),

	// class E, the effect depends on what is installed on the host
	"StorageOpt":   compared("selects a storage driver and its options"),
	"VolumeDriver": compared("selects the driver backing anonymous volumes"),
	"Annotations":  compared("arbitrary metadata handed to a runtime the proxy cannot inspect"),

	// class C, availability and resource consumption
	"ConsoleSize": forwarded("terminal geometry"),
	"ShmSize":     forwarded("resource limit"),

	// class D, container lifecycle, name resolution, daemon defaults
	"AutoRemove":    forwarded("container lifecycle"),
	"RestartPolicy": forwarded("container lifecycle"),
	"LogConfig":     forwarded("driver choice belongs to the host administrator; it consumes disk and may reach a network"),
	"DNS":           forwarded("name resolution inside the container"),
	"DNSOptions":    forwarded("name resolution inside the container"),
	"DNSSearch":     forwarded("name resolution inside the container"),
	"ExtraHosts":    forwarded("name resolution inside the container"),
	"Links":         forwarded("adds a name to /etc/hosts; it adds no reachability"),
	"Init":          forwarded("runs as the container's own PID 1, inside its namespaces"),
	"OomScoreAdj":   forwarded("resource limit"),
}

// resourcesFields classifies container.Resources, which HostConfig embeds. Devices
// and device requests are class A here, since they hand the container a host device.
var resourcesFields = map[string]fieldDecision{
	"Devices":           compared("host device access"),
	"DeviceCgroupRules": compared("device cgroup rules"),
	"DeviceRequests":    compared("device requests, including GPU requests"),
	"CgroupParent":      compared("placement in the host cgroup hierarchy"),

	"Memory":               forwarded("resource limit"),
	"MemoryReservation":    forwarded("resource limit"),
	"MemorySwap":           forwarded("resource limit"),
	"MemorySwappiness":     forwarded("resource limit"),
	"KernelMemory":         forwarded("resource limit"),
	"KernelMemoryTCP":      forwarded("resource limit"),
	"NanoCPUs":             forwarded("resource limit"),
	"CPUShares":            forwarded("resource limit"),
	"CpusetCpus":           forwarded("resource limit"),
	"CpusetMems":           forwarded("resource limit"),
	"CPUQuota":             forwarded("resource limit"),
	"CPUPeriod":            forwarded("resource limit"),
	"CPUCount":             forwarded("resource limit"),
	"CPUPercent":           forwarded("resource limit"),
	"CPURealtimePeriod":    forwarded("resource limit"),
	"CPURealtimeRuntime":   forwarded("resource limit"),
	"PidsLimit":            forwarded("resource limit"),
	"OomKillDisable":       forwarded("resource limit"),
	"Ulimits":              forwarded("resource limit"),
	"BlkioWeight":          forwarded("resource limit"),
	"BlkioWeightDevice":    forwarded("resource limit"),
	"BlkioDeviceReadBps":   forwarded("resource limit"),
	"BlkioDeviceWriteBps":  forwarded("resource limit"),
	"BlkioDeviceReadIOps":  forwarded("resource limit"),
	"BlkioDeviceWriteIOps": forwarded("resource limit"),
	"IOMaximumIOps":        forwarded("resource limit"),
	"IOMaximumBandwidth":   forwarded("resource limit"),
}

// configFields classifies container.Config.
var configFields = map[string]fieldDecision{
	// class A
	"Image":           compared("the image decides what runs with the container's capabilities"),
	"Entrypoint":      compared("what the image's entrypoint is replaced with"),
	"User":            compared("privilege inside the container"),
	"NetworkDisabled": compared("the network_mode: disabled boundary"),
	"Volumes":         refused("declares an anonymous volume, which is a mount"),
	"ExposedPorts":    forwarded("cannot create a host listener once PublishAllPorts is refused"),

	// class D: what `docker compose run` exists to change, plus the rest
	"Cmd":          forwarded("the command override is the point of docker compose run"),
	"Env":          forwarded("environment"),
	"Labels":       forwarded("read only to name the service to compare against and to require a one-off container; never an authority"),
	"Hostname":     forwarded("container-local identity"),
	"Domainname":   forwarded("container-local identity"),
	"WorkingDir":   forwarded("container-local layout"),
	"Tty":          forwarded("terminal attachment"),
	"OpenStdin":    forwarded("terminal attachment"),
	"StdinOnce":    forwarded("terminal attachment"),
	"AttachStdin":  forwarded("terminal attachment"),
	"AttachStdout": forwarded("terminal attachment"),
	"AttachStderr": forwarded("terminal attachment"),
	"Healthcheck":  forwarded("container lifecycle"),
	"StopSignal":   forwarded("container lifecycle"),
	"StopTimeout":  forwarded("container lifecycle"),
	"Shell":        forwarded("how the image's shell form is parsed"),
	"MacAddress":   forwarded("endpoint metadata"),
	"OnBuild":      forwarded("ONBUILD triggers run only in a build or a commit, neither of which is reachable here"),
	"ArgsEscaped":  forwarded("read only by the Windows OCI path; the proxy speaks to a Linux daemon"),
}

// endpointFields classifies the parts of network.EndpointSettings the policy reads.
// Only the map keys are compared.
var endpointFields = map[string]fieldDecision{
	"Aliases":             forwarded("reachability metadata inside an attached network"),
	"MacAddress":          forwarded("reachability metadata inside an attached network"),
	"DriverOpts":          forwarded("reachability metadata inside an attached network"),
	"GwPriority":          forwarded("reachability metadata inside an attached network"),
	"IPAMConfig":          forwarded("static addressing inside an attached network"),
	"Links":               forwarded("reachability metadata inside an attached network"),
	"NetworkID":           forwarded("assigned by the daemon"),
	"EndpointID":          forwarded("assigned by the daemon"),
	"Gateway":             forwarded("assigned by the daemon"),
	"IPAddress":           forwarded("assigned by the daemon"),
	"IPPrefixLen":         forwarded("assigned by the daemon"),
	"IPv6Gateway":         forwarded("assigned by the daemon"),
	"GlobalIPv6Address":   forwarded("assigned by the daemon"),
	"GlobalIPv6PrefixLen": forwarded("assigned by the daemon"),
	"DNSNames":            forwarded("assigned by the daemon"),
}

// execOptionsFields classifies container.ExecOptions. An exec runs inside a container
// the proxy has already judged, so most of it is the client's to choose: what it asks
// for is a command, which the container's own privilege is then applied to.
var execOptionsFields = map[string]fieldDecision{
	"User":       refused("an exec may not run as a user of its own"),
	"Privileged": refused("an exec adds no privilege of its own to the container's"),

	"Tty":          compared("the terminal the exec was created with decides how its output is framed"),
	"AttachStdin":  forwarded("terminal attachment"),
	"AttachStdout": forwarded("terminal attachment"),
	"AttachStderr": forwarded("terminal attachment"),
	"ConsoleSize":  forwarded("initial terminal geometry"),
	"DetachKeys":   forwarded("terminal detach sequence"),
	"Cmd":          forwarded("the command an exec runs is the point of docker compose exec"),
	"Env":          forwarded("environment"),
	"WorkingDir":   forwarded("container-local layout"),
	"Detach":       forwarded("the daemon ignores it; the start decides whether the exec is attached"),
}

// execStartOptionsFields classifies container.ExecStartOptions.
var execStartOptionsFields = map[string]fieldDecision{
	"Tty":         compared("a start may only ask for the terminal the exec was created with"),
	"Detach":      forwarded("a detached start answers with a body rather than a stream"),
	"ConsoleSize": forwarded("initial terminal geometry"),
}

// TestEveryRequestFieldIsClassified checks the inventory against the Moby types both
// ways. A bump adds a field with no decision and leaves one behind for a lost field.
func TestEveryRequestFieldIsClassified(t *testing.T) {
	tables := map[string]map[string]fieldDecision{
		"Config":           configFields,
		"HostConfig":       hostConfigFields,
		"Resources":        resourcesFields,
		"EndpointSettings": endpointFields,
		"ExecOptions":      execOptionsFields,
		"ExecStartOptions": execStartOptionsFields,
	}
	declared := map[string]map[string]bool{
		"Config":           declaredFields(reflect.TypeOf(container.Config{})),
		"HostConfig":       declaredFields(reflect.TypeOf(container.HostConfig{})),
		"Resources":        declaredFields(reflect.TypeOf(container.Resources{})),
		"EndpointSettings": declaredFields(reflect.TypeOf(network.EndpointSettings{})),
		"ExecOptions":      declaredFields(reflect.TypeOf(container.ExecOptions{})),
		"ExecStartOptions": declaredFields(reflect.TypeOf(container.ExecStartOptions{})),
	}

	for typeName, table := range tables {
		present := declared[typeName]
		for name, decision := range table {
			if !present[name] {
				t.Errorf("%s.%s is classified but no longer exists in the Moby types", typeName, name)
				continue
			}
			switch decision.class {
			case classCompared, classRefused, classForwarded:
			default:
				t.Errorf("%s.%s has an unknown class %q", typeName, name, decision.class)
			}
			if decision.reason == "" {
				t.Errorf("%s.%s has no stated reason", typeName, name)
			}
		}
		for name := range present {
			if _, ok := table[name]; ok {
				continue
			}
			// An embedded struct is classified under its own type name, which covers
			// HostConfig's embedded container.Resources without classifying it twice.
			if _, ok := tables[name]; ok {
				continue
			}
			t.Errorf("%s.%s is not classified; a Moby bump that adds a field fails here until it is",
				typeName, name)
		}
	}
}

// declaredFields returns the fields a type declares itself, named by the embedded
// struct's type where it embeds one.
func declaredFields(typ reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		if field.Anonymous {
			out[field.Type.Name()] = true
			continue
		}
		out[field.Name] = true
	}
	return out
}

// TestClassificationCoversTheCreateRequestShape keeps the top level of the request
// in view. A fourth top-level field there is a new decision surface to classify.
func TestClassificationCoversTheCreateRequestShape(t *testing.T) {
	typ := reflect.TypeOf(container.CreateRequest{})
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		names = append(names, typ.Field(i).Name)
	}
	joined := strings.Join(names, ",")
	if joined != "Config,HostConfig,NetworkingConfig" {
		t.Errorf("container.CreateRequest gained or lost a field: %s", joined)
	}
}
