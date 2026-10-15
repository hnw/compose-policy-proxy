package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// mode distinguishes create requests from inspect results. An inspect result
// cannot tell a client requested value from a daemon filled one.
type mode int

const (
	// modeCreate validates a request the client is about to send.
	modeCreate mode = iota
	// modeInspect validates the state of a container that already exists.
	modeInspect
)

// compareService reports whether req stays within the capability that service
// grants, in the given mode. The request is validated once, here.
func compareService(
	project *types.Project,
	service types.ServiceConfig,
	req *container.CreateRequest,
	m mode,
) error {
	if req == nil {
		return deny(service.Name, "request", "container create request is empty")
	}
	if req.Config == nil {
		return deny(service.Name, "request", "container config is empty")
	}
	if req.HostConfig == nil {
		// A create request without a HostConfig is not a container Docker would
		// accept, and reading it as "nothing restricted" is the wrong default.
		return deny(service.Name, "request", "container host config is empty")
	}

	// The order is fixed so that a request with several problems always reports
	// the same, most fundamental one first. inventory_test.go classifies the rest.
	comparisons := []func() error{
		func() error { return compareDockerOnlyFields(service, req, m) },
		func() error { return compareImage(project, service, req) },
		func() error { return compareEntrypoint(service, req) },
		func() error { return equal(service.Name, "Config.User", service.User, req.Config.User) },
		func() error {
			return equalSet(service.Name, "HostConfig.GroupAdd", service.GroupAdd, req.HostConfig.GroupAdd)
		},
		func() error {
			return equal(service.Name, "HostConfig.Privileged", service.Privileged, req.HostConfig.Privileged)
		},
		func() error { return compareCapabilities(service, req) },
		func() error { return compareSecurityOpt(service, req, m) },
		func() error {
			return equal(service.Name, "HostConfig.ReadonlyRootfs", service.ReadOnly, req.HostConfig.ReadonlyRootfs)
		},
		func() error { return compareRuntime(service, req, m) },
		func() error {
			return equalMap(service.Name, "HostConfig.Sysctls", map[string]string(service.Sysctls), req.HostConfig.Sysctls)
		},
		func() error { return compareNamespaces(service, req, m) },
		func() error { return compareDevices(service, req) },
		func() error {
			return equal(service.Name, "HostConfig.CgroupParent", service.CgroupParent, req.HostConfig.CgroupParent)
		},
		func() error {
			return equal(service.Name, "HostConfig.Isolation", service.Isolation, string(req.HostConfig.Isolation))
		},
		func() error {
			return equalSet(service.Name, "HostConfig.VolumesFrom", service.VolumesFrom, req.HostConfig.VolumesFrom)
		},
		func() error { return compareHostDependentFields(service, req) },
		func() error { return compareNetworkDisabled(service, req) },
		func() error { return compareMounts(project, service, req) },
		func() error { return compareNetworks(project, service, req) },
		func() error { return comparePorts(service, req) },
	}
	for _, cmp := range comparisons {
		if err := cmp(); err != nil {
			return err
		}
	}
	return nil
}

func compareDockerOnlyFields(service types.ServiceConfig, req *container.CreateRequest, m mode) error {
	hc := req.HostConfig
	// Current Engine versions ignore ContainerIDFile, but its API contract names
	// a host path to write. Keep it refused in case an Engine implements it.
	if hc.ContainerIDFile != "" {
		return denyf(service.Name, "HostConfig.ContainerIDFile",
			"a container id file at host path %q is not declared by compose", hc.ContainerIDFile)
	}
	if hc.PublishAllPorts {
		return deny(service.Name, "HostConfig.PublishAllPorts",
			"compose does not allow publishing all ports")
	}
	// Config.Volumes declares anonymous volumes, so it is a mount declaration
	// reached outside the canonical mount set rather than through it.
	if len(req.Config.Volumes) != 0 {
		return deny(service.Name, "Config.Volumes",
			"an anonymous volume is declared outside the mount entries the policy compares")
	}

	// The next group is create-path only, since the daemon substitutes or
	// normalises each of these when a request omits it.
	if m == modeCreate {
		// Compose empties these for security_opt "systempaths=unconfined", so a
		// value here was invented by the client.
		if len(hc.MaskedPaths) != 0 {
			return denyf(service.Name, "HostConfig.MaskedPaths",
				"compose cannot express masked paths, so an override is refused")
		}
		if len(hc.ReadonlyPaths) != 0 {
			return denyf(service.Name, "HostConfig.ReadonlyPaths",
				"compose cannot express read-only paths, so an override is refused")
		}
		// Compose only maps CgroupnsMode. This field names a cgroup directly, so
		// the proxy cannot tell what it selects.
		if hc.Cgroup != "" {
			return denyf(service.Name, "HostConfig.Cgroup",
				"compose cannot express cgroup %q", string(hc.Cgroup))
		}
	}
	return nil
}

func compareImage(project *types.Project, service types.ServiceConfig, req *container.CreateRequest) error {
	return equal(service.Name, "Config.Image", compose.ImageName(project, service), req.Config.Image)
}

// compareEntrypoint compares the entrypoint exactly. A command override is allowed
// because its caller already holds the container's grants.
func compareEntrypoint(service types.ServiceConfig, req *container.CreateRequest) error {
	var want []string
	if service.Entrypoint != nil {
		want = []string(service.Entrypoint)
	}
	got := []string(req.Config.Entrypoint)
	if !slices.Equal(want, got) {
		return denyf(service.Name, "Config.Entrypoint",
			"compose declares entrypoint %v, found %v", want, got)
	}
	return nil
}

// equal refuses a request whose value for field is not the one Compose declares.
func equal[T comparable](service, field string, want, got T) error {
	if want == got {
		return nil
	}
	return denyMismatch(service, field, want, got)
}

// equalSet refuses a request whose set of strings is not the declared one. Order,
// duplicates and nil versus empty carry no meaning for these fields.
func equalSet(service, field string, want, got []string) error {
	if maps.Equal(stringSet(want), stringSet(got)) {
		return nil
	}
	return denyMismatch(service, field, want, got)
}

// equalMap refuses a request whose string map is not the declared one. A nil and
// an empty map are the same map, as Docker decodes an absent JSON object to nil.
func equalMap(service, field string, want, got map[string]string) error {
	if maps.Equal(want, got) {
		return nil
	}
	return denyMismatch(service, field, want, got)
}

func denyMismatch(service, field string, want, got any) error {
	return denyf(service, field, "compose declares %v, found %v", quoted(want), quoted(got))
}

// quoted writes a string value as a quoted string, so that an empty one is visible.
func quoted(v any) any {
	if s, ok := v.(string); ok {
		return strconv.Quote(s)
	}
	return v
}

// compareCapabilities applies a subset rule rather than an exact match. The request
// may add fewer capabilities and drop more, but not re-add one Compose dropped.
func compareCapabilities(service types.ServiceConfig, req *container.CreateRequest) error {
	hc := req.HostConfig

	wantAdd := canonicalCapabilities(service.CapAdd)
	gotAdd := canonicalCapabilities(hc.CapAdd)
	if !capabilitiesSubset(gotAdd, wantAdd) {
		return denyf(service.Name, "HostConfig.CapAdd",
			"compose declares cap_add %v, found %v", wantAdd, gotAdd)
	}
	wantDrop := canonicalCapabilities(service.CapDrop)
	gotDrop := canonicalCapabilities(hc.CapDrop)
	if !capabilitiesSubset(wantDrop, gotDrop) {
		return denyf(service.Name, "HostConfig.CapDrop",
			"compose requires dropping %v, but they are not dropped", missingFrom(gotDrop, wantDrop))
	}
	// Re-adding a dropped capability hands back the privilege even though the
	// subset check above passed.
	dropped := stringSet(wantDrop)
	for _, c := range gotAdd {
		if _, ok := dropped[c]; ok {
			return denyf(service.Name, "HostConfig.CapAdd",
				"capability %s is dropped by compose and cannot be added back", c)
		}
	}
	return nil
}

func missingFrom(have, want []string) []string {
	set := stringSet(have)
	var out []string
	for _, w := range want {
		if _, ok := set[w]; !ok {
			out = append(out, w)
		}
	}
	return out
}

type securityOpt struct {
	key    string
	value  string
	hasVal bool
}

// text renders one option for a refusal. A seccomp profile is a whole JSON
// document the Compose file owns, so its key stands for it.
func (s securityOpt) text() string {
	if s.key == "seccomp" {
		return s.key
	}
	if !s.hasVal {
		return s.key
	}
	return s.key + "=" + s.value
}

// isSeccompProfileFile reports whether the option names a profile file rather than
// a value the daemon resolves. Compose sends the file contents, not the filename.
func (s securityOpt) isSeccompProfileFile() bool {
	return s.key == "seccomp" && s.hasVal && s.value != "unconfined" && s.value != "builtin"
}

// composeSecurityOpts mirrors how Compose turns security_opt into
// HostConfig.SecurityOpt, so both sides are compared in one representation.
func composeSecurityOpts(service types.ServiceConfig) ([]securityOpt, error) {
	var out []securityOpt
	for _, raw := range service.SecurityOpt {
		// Compose empties MaskedPaths/ReadonlyPaths for this, and
		// compareDockerOnlyFields already requires both empty.
		if raw == "systempaths=unconfined" {
			continue
		}
		opt, err := parseSecurityOpt(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, opt)
	}
	return out, nil
}

func parseSecurityOpt(raw string) (securityOpt, error) {
	parts := strings.SplitN(raw, "=", 2)
	if len(parts) == 1 && parts[0] != "no-new-privileges" {
		if strings.Contains(raw, ":") {
			parts = strings.SplitN(raw, ":", 2)
		} else {
			return securityOpt{}, fmt.Errorf("invalid security_opt %q", raw)
		}
	}
	opt := securityOpt{key: parts[0]}
	if len(parts) == 2 {
		opt.value, opt.hasVal = parts[1], true
	}
	// Compose writes the bare form when it turns the flag on, and the daemon reads a
	// bare value as on rather than as a missing one.
	if opt.key == "no-new-privileges" && !opt.hasVal {
		opt.value, opt.hasVal = "true", true
	}
	return opt, nil
}

// resolveSeccompProfiles replaces every declared seccomp profile file with the JSON
// Compose sends, so no decision reads the file system at request time.
func resolveSeccompProfiles(project *types.Project) (*types.Project, error) {
	resolved := *project
	var err error
	if resolved.Services, err = resolveSeccompInServices(project, project.Services); err != nil {
		return nil, err
	}
	if resolved.DisabledServices, err = resolveSeccompInServices(project, project.DisabledServices); err != nil {
		return nil, err
	}
	return &resolved, nil
}

func resolveSeccompInServices(project *types.Project, services types.Services) (types.Services, error) {
	out := make(types.Services, len(services))
	for name, service := range services {
		opts, err := resolveSeccompInSecurityOpts(project, service.SecurityOpt)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", name, err)
		}
		service.SecurityOpt = opts
		out[name] = service
	}
	return out, nil
}

func resolveSeccompInSecurityOpts(project *types.Project, rawOpts []string) ([]string, error) {
	out := make([]string, 0, len(rawOpts))
	for _, raw := range rawOpts {
		opt, err := parseSecurityOpt(raw)
		if err != nil {
			return nil, err
		}
		if !opt.isSeccompProfileFile() {
			out = append(out, raw)
			continue
		}
		profile, err := readSeccompProfile(project, opt.value)
		if err != nil {
			return nil, err
		}
		out = append(out, opt.key+"="+profile)
	}
	return out, nil
}

func readSeccompProfile(project *types.Project, name string) (string, error) {
	data, err := os.ReadFile(project.RelativePath(name))
	if err != nil {
		return "", fmt.Errorf("cannot read seccomp profile %q: %w", name, err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		return "", fmt.Errorf("seccomp profile %q is not valid JSON: %w", name, err)
	}
	return buf.String(), nil
}

func compareSecurityOpt(service types.ServiceConfig, req *container.CreateRequest, m mode) error {
	want, err := composeSecurityOpts(service)
	if err != nil {
		return denyf(service.Name, "HostConfig.SecurityOpt", "%v", err)
	}

	got := make(map[string]securityOpt, len(req.HostConfig.SecurityOpt))
	for _, raw := range req.HostConfig.SecurityOpt {
		opt, err := parseSecurityOpt(raw)
		if err != nil {
			return denyf(service.Name, "HostConfig.SecurityOpt", "%v", err)
		}
		got[opt.key] = opt
	}

	allowed := make(map[string]securityOpt, len(want))
	for _, opt := range want {
		allowed[opt.key] = opt
	}

	// Every option Compose asked for must still be in effect, unchanged.
	for _, opt := range want {
		found, ok := got[opt.key]
		if !ok {
			return denyf(service.Name, "HostConfig.SecurityOpt",
				"compose requires security_opt %q, found none", opt.text())
		}
		if opt.key == "no-new-privileges" {
			// Turning the flag off restores privilege, leaving it on is fine.
			if isTruthy(opt.value) != isTruthy(found.value) {
				return denyf(service.Name, "HostConfig.SecurityOpt",
					"compose requires security_opt %q, found %q", opt.text(), found.text())
			}
			continue
		}
		if found.value != opt.value {
			// Neither side of a seccomp profile can be written out, so only that
			// they differ is said.
			if opt.key == "seccomp" {
				return denyf(service.Name, "HostConfig.SecurityOpt",
					"compose requires security_opt %q, found a different seccomp profile", opt.key)
			}
			return denyf(service.Name, "HostConfig.SecurityOpt",
				"compose requires security_opt %q, found %q", opt.text(), found.text())
		}
	}

	// Undeclared options are refused on create because their security impact varies.
	if m != modeInspect {
		for key, found := range got {
			if _, ok := allowed[key]; !ok {
				return denyf(service.Name, "HostConfig.SecurityOpt",
					"security option %q is not declared by compose", found.text())
			}
		}
	}
	return nil
}

func isTruthy(s string) bool {
	v, ok := parseBoolOption(s)
	return ok && v
}

// compareRuntime is create-path only. An existing container always reports a runtime
// the daemon chose, which an inspect result cannot attribute to the client.
func compareRuntime(service types.ServiceConfig, req *container.CreateRequest, m mode) error {
	if m == modeInspect {
		return nil
	}
	return equal(service.Name, "HostConfig.Runtime", service.Runtime, req.HostConfig.Runtime)
}

// compareNamespaces is create-path only, for the same reason as compareRuntime.
func compareNamespaces(service types.ServiceConfig, req *container.CreateRequest, m mode) error {
	if m == modeInspect {
		return nil
	}
	hc := req.HostConfig

	// Docker resolves an omitted CgroupnsMode from the daemon's own
	// --default-cgroupns-mode, so an omission is not the private namespace
	// compose declared, and the two are compared as written.
	gotCgroup, wantCgroup := strings.TrimSpace(string(hc.CgroupnsMode)), strings.TrimSpace(service.Cgroup)
	if gotCgroup != wantCgroup {
		return denyf(service.Name, "HostConfig.CgroupnsMode",
			"compose declares %q, found %q", wantCgroup, gotCgroup)
	}

	pairs := []struct {
		field string
		want  string
		got   string
	}{
		{"HostConfig.PidMode", service.Pid, string(hc.PidMode)},
		{"HostConfig.IpcMode", service.Ipc, string(hc.IpcMode)},
		{"HostConfig.UsernsMode", service.UserNSMode, string(hc.UsernsMode)},
		{"HostConfig.UTSMode", service.Uts, string(hc.UTSMode)},
	}
	for _, p := range pairs {
		if !sameNamespace(p.want, p.got) {
			return denyf(service.Name, p.field, "compose declares %q, found %q", p.want, p.got)
		}
	}
	return nil
}

// sameNamespace treats an empty selector and "private" as the same thing, since
// the daemon builds those namespaces itself when the request names none.
func sameNamespace(got, want string) bool {
	got, want = strings.TrimSpace(got), strings.TrimSpace(want)
	if got == want {
		return true
	}
	return isPrivate(got) && isPrivate(want)
}

func isPrivate(s string) bool {
	return s == "" || s == "private"
}

type deviceSpec struct {
	source      string
	target      string
	permissions string
}

// compareDevices compares device mappings, cgroup rules and requests exactly. Driver
// options are compared as resolved values rather than interpreted.
func compareDevices(service types.ServiceConfig, req *container.CreateRequest) error {
	hc := req.HostConfig

	var wantDevices []deviceSpec
	var cdiNames []string
	for _, d := range service.Devices {
		perms := d.Permissions
		if perms == "" {
			perms = "rwm"
		}
		if d.Source == d.Target && isCDIQualifiedName(d.Source) {
			cdiNames = append(cdiNames, d.Source)
			continue
		}
		wantDevices = append(wantDevices, deviceSpec{source: d.Source, target: d.Target, permissions: perms})
	}
	var gotDevices []deviceSpec
	for _, d := range hc.Devices {
		perms := d.CgroupPermissions
		if perms == "" {
			perms = "rwm"
		}
		gotDevices = append(gotDevices, deviceSpec{source: d.PathOnHost, target: d.PathInContainer, permissions: perms})
	}
	if !slices.Equal(sortedDevices(wantDevices), sortedDevices(gotDevices)) {
		return denyf(service.Name, "HostConfig.Devices",
			"compose declares devices %v, found %v", sortedDevices(wantDevices), sortedDevices(gotDevices))
	}

	if err := equalSet(service.Name, "HostConfig.DeviceCgroupRules",
		service.DeviceCgroupRules, hc.DeviceCgroupRules); err != nil {
		return err
	}

	wantRequests := expectedDeviceRequests(service, cdiNames)
	gotRequests := normalizeDeviceRequests(hc.DeviceRequests)
	if !slices.Equal(wantRequests, gotRequests) {
		return denyf(service.Name, "HostConfig.DeviceRequests",
			"compose declares device requests %v, found %v", wantRequests, gotRequests)
	}
	return nil
}

func sortedDevices(in []deviceSpec) []deviceSpec {
	out := append([]deviceSpec(nil), in...)
	slices.SortFunc(out, func(a, b deviceSpec) int {
		if c := strings.Compare(a.source, b.source); c != 0 {
			return c
		}
		if c := strings.Compare(a.target, b.target); c != 0 {
			return c
		}
		return strings.Compare(a.permissions, b.permissions)
	})
	return out
}

// expectedDeviceRequests reproduces what Compose derives from a service, one "cdi"
// request for CDI names plus one per `gpus` entry with "gpu" appended.
func expectedDeviceRequests(service types.ServiceConfig, cdiNames []string) []string {
	var out []string
	if len(cdiNames) > 0 {
		out = append(out, deviceRequestKey(container.DeviceRequest{
			Driver:    "cdi",
			DeviceIDs: cdiNames,
		}))
	}
	for _, g := range service.Gpus {
		caps := make([]string, 0, len(g.Capabilities)+1)
		caps = append(caps, g.Capabilities...)
		caps = append(caps, "gpu")
		out = append(out, deviceRequestKey(container.DeviceRequest{
			Driver:       g.Driver,
			Count:        int(g.Count),
			DeviceIDs:    g.IDs,
			Capabilities: [][]string{caps},
			Options:      map[string]string(g.Options),
		}))
	}
	slices.Sort(out)
	return out
}

// normalizeDeviceRequests sorts the encoded requests, so that the order Docker sent
// them in does not read as a difference.
func normalizeDeviceRequests(in []container.DeviceRequest) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, deviceRequestKey(r))
	}
	slices.Sort(out)
	return out
}

// normalizedDeviceRequest is a device request with the parts that carry no meaning for
// the comparison canonicalized away: an absent collection and an empty one are the same.
type normalizedDeviceRequest struct {
	Driver       string            `json:"driver"`
	Count        int               `json:"count"`
	DeviceIDs    []string          `json:"deviceIDs"`
	Capabilities [][]string        `json:"capabilities"`
	Options      map[string]string `json:"options"`
}

// deviceRequestKey encodes a request as JSON, so no separator can make two different
// requests share one key. The types here cannot fail to encode.
func deviceRequestKey(r container.DeviceRequest) string {
	key := normalizedDeviceRequest{
		Driver:       r.Driver,
		Count:        r.Count,
		DeviceIDs:    dedupNonEmpty(r.DeviceIDs),
		Capabilities: [][]string{},
		Options:      map[string]string{},
	}
	if r.Options != nil {
		key.Options = r.Options
	}
	for _, set := range r.Capabilities {
		sorted := append([]string(nil), set...)
		slices.Sort(sorted)
		key.Capabilities = append(key.Capabilities, sorted)
	}

	encoded, _ := json.Marshal(key)
	return string(encoded)
}

// isCDIQualifiedName reports whether a device source names a CDI device, which
// Compose turns into a request rather than a host path.
func isCDIQualifiedName(s string) bool {
	host, rest, ok := strings.Cut(s, "/")
	return ok && strings.Contains(host, ".") && rest != ""
}

func boolValue(b *bool) bool {
	return b != nil && *b
}

// compareHostDependentFields requires an exact match on the three fields that depend
// on the host, since the proxy cannot say which value of a driver option is safer.
// A driver option may hold credentials, so a refusal says that it differs, not what.
func compareHostDependentFields(service types.ServiceConfig, req *container.CreateRequest) error {
	hc := req.HostConfig

	if err := equal(service.Name, "HostConfig.VolumeDriver", service.VolumeDriver, hc.VolumeDriver); err != nil {
		return err
	}
	if !maps.Equal(map[string]string(service.StorageOpt), hc.StorageOpt) {
		return deny(service.Name, "HostConfig.StorageOpt", "storage options differ from compose")
	}
	if !maps.Equal(map[string]string(service.Annotations), hc.Annotations) {
		return deny(service.Name, "HostConfig.Annotations", "annotations differ from compose")
	}
	return nil
}

func compareNetworkDisabled(service types.ServiceConfig, req *container.CreateRequest) error {
	wantDisabled := service.NetworkMode == "disabled"
	if wantDisabled != req.Config.NetworkDisabled {
		return denyf(service.Name, "Config.NetworkDisabled",
			"compose implies NetworkDisabled=%t, found %t", wantDisabled, req.Config.NetworkDisabled)
	}
	return nil
}

// comparePorts allows the request to omit declared bindings, as `compose run` does,
// but every binding it requests must be declared. ExposedPorts cannot listen.
func comparePorts(service types.ServiceConfig, req *container.CreateRequest) error {
	declaredBindings, err := declaredPorts(service)
	if err != nil {
		return err
	}

	for port, bindings := range req.HostConfig.PortBindings {
		want, ok := declaredBindings[port]
		if !ok {
			return denyf(service.Name, "HostConfig.PortBindings",
				"port %s is not declared by compose", port)
		}
		if !sameBindings(want, bindings) {
			return denyf(service.Name, "HostConfig.PortBindings",
				"compose publishes %v for %s, found %v", want, port, bindings)
		}
	}
	return nil
}

// declaredPorts computes the bindings Compose declares. Only `ports` produces one,
// as `expose` declares a port the image listens on and never publishes.
func declaredPorts(service types.ServiceConfig) (map[nat.Port][]nat.PortBinding, error) {
	bindings := map[nat.Port][]nat.PortBinding{}

	for _, p := range service.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		port, err := nat.NewPort(proto, strconv.FormatUint(uint64(p.Target), 10))
		if err != nil {
			return nil, denyf(service.Name, "ports",
				"compose declares an invalid port %d/%s", p.Target, proto)
		}
		bindings[port] = append(bindings[port], nat.PortBinding{HostIP: p.HostIP, HostPort: p.Published})
	}
	return bindings, nil
}

// sameBindings compares one port's bindings as multisets. Repeating a binding stands
// in for a missing one, so membership alone would accept the wrong list.
func sameBindings(want, got []nat.PortBinding) bool {
	if len(want) != len(got) {
		return false
	}
	taken := make([]bool, len(want))
	for _, b := range got {
		found := false
		for i, w := range want {
			if !taken[i] && sameIP(w.HostIP, b.HostIP) && w.HostPort == b.HostPort {
				taken[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// compareNetworks checks NetworkMode and the set of endpoint names. Endpoint metadata
// stays inside the network the project already attached the container to.
func compareNetworks(project *types.Project, service types.ServiceConfig, req *container.CreateRequest) error {
	endpoints := map[string]bool{}
	if req.NetworkingConfig != nil {
		for name := range req.NetworkingConfig.EndpointsConfig {
			endpoints[name] = true
		}
	}
	gotMode := string(req.HostConfig.NetworkMode)

	// A service pinned to a namespace or to another container takes no
	// endpoints. This is where host networking and `container:<id>` are stopped.
	if service.NetworkMode != "" {
		if service.NetworkMode != gotMode {
			return denyf(service.Name, "HostConfig.NetworkMode",
				"compose declares network_mode %q, found %q", service.NetworkMode, gotMode)
		}
		if len(endpoints) != 0 {
			return denyf(service.Name, "NetworkingConfig.EndpointsConfig",
				"network_mode %q takes no network endpoints, found %d", service.NetworkMode, len(endpoints))
		}
		return nil
	}

	keys := service.NetworksByPriority()

	if len(project.Networks) == 0 {
		if gotMode != "none" {
			return denyf(service.Name, "HostConfig.NetworkMode",
				"compose project declares no network, found network mode %q", gotMode)
		}
		if len(endpoints) != 0 {
			return denyf(service.Name, "NetworkingConfig.EndpointsConfig",
				"compose project declares no network, found %d networks attached", len(endpoints))
		}
		return nil
	}

	primary := compose.DefaultNetworkKey
	if len(keys) > 0 {
		primary = keys[0]
	}
	wantMode, err := compose.NetworkName(project, primary)
	if err != nil {
		return denyf(service.Name, "HostConfig.NetworkMode", "%v", err)
	}
	if gotMode != wantMode {
		return denyf(service.Name, "HostConfig.NetworkMode",
			"compose attaches this service to %q, found network mode %q", wantMode, gotMode)
	}

	// Endpoints must be exactly the service's networks. An extra one is an
	// undeclared attachment, a missing one is a container Compose did not describe.
	if len(endpoints) != len(keys) {
		return denyf(service.Name, "NetworkingConfig.EndpointsConfig",
			"compose attaches this service to %d networks, found %d", len(keys), len(endpoints))
	}
	for _, key := range keys {
		name, err := compose.NetworkName(project, key)
		if err != nil {
			return denyf(service.Name, "NetworkingConfig.EndpointsConfig", "%v", err)
		}
		if !endpoints[name] {
			return denyf(service.Name, "NetworkingConfig.EndpointsConfig",
				"network %q (%s) is not attached", name, key)
		}
	}
	return nil
}
