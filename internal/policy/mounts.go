package policy

import (
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// Docker represents Compose mounts through Binds, Mounts and Tmpfs, canonicalized
// before comparison so the policy does not depend on the wire representation.

type mountKind string

const (
	mountKindBind   mountKind = "bind"
	mountKindVolume mountKind = "volume"
	mountKindTmpfs  mountKind = "tmpfs"
	mountKindImage  mountKind = "image"
)

// mountSpec contains only the mount properties the policy compares. Anything not
// present here is class C or D and forwarded.
type mountSpec struct {
	kind     mountKind
	target   string
	source   string
	readOnly bool

	// Bind options.
	propagation            string
	selinux                string
	nonRecursive           bool
	readOnlyNonRecursive   bool
	readOnlyForceRecursive bool
	createMountpoint       bool

	// Named volume options.
	volumeSubpath    string
	volumeNoCopy     bool
	volumeDriver     string
	volumeDriverOpts map[string]string
	volumeLabels     map[string]string

	// Image mount options.
	imageSubpath string
}

// compareMounts checks that the request's mounts are exactly the ones Compose
// declares, in the reduced form above.
func compareMounts(project *types.Project, service types.ServiceConfig, req *container.CreateRequest) error {
	hc := req.HostConfig

	expected, err := expectedMounts(project, service)
	if err != nil {
		if pe, ok := Inspect(err); ok {
			pe.Service = service.Name
			return pe
		}
		return err
	}

	// Compose puts named volumes and host paths in the same Binds list, so only
	// a name the project declares as a volume can be one.
	volumeNames := make(map[string]struct{}, len(project.Volumes))
	for _, name := range compose.VolumeNames(project) {
		volumeNames[name] = struct{}{}
	}

	seen := make(map[string]mountSpec, len(expected))

	consume := func(spec mountSpec, origin string) error {
		// Two entries for one container path is ambiguous, and the second could
		// be the one that wins.
		if prev, dup := seen[spec.target]; dup {
			return denyf(service.Name, origin,
				"container path %q is mounted twice (%s and %s)", spec.target, prev.kind, spec.kind)
		}
		want, ok := expected[spec.target]
		if !ok {
			return denyf(service.Name, origin,
				"container path %q is not declared by compose", spec.target)
		}
		if err := compareMountSpec(service, origin, want, spec); err != nil {
			return err
		}
		seen[spec.target] = spec
		return nil
	}

	for _, m := range hc.Mounts {
		if err := consume(mountSpecFromMount(m), "HostConfig.Mounts"); err != nil {
			return err
		}
	}
	for _, raw := range hc.Binds {
		spec, err := mountSpecFromBind(raw, volumeNames)
		if err != nil {
			return denyf(service.Name, "HostConfig.Binds", "%v", err)
		}
		if err := consume(spec, "HostConfig.Binds"); err != nil {
			return err
		}
	}
	for path, options := range hc.Tmpfs {
		if err := consume(mountSpecFromTmpfs(path, options), "HostConfig.Tmpfs"); err != nil {
			return err
		}
	}

	// In either direction the request must describe the service, not a subset.
	for target, want := range expected {
		if _, ok := seen[target]; !ok {
			return denyf(service.Name, "HostConfig",
				"compose declares a %s mount at %q, found none", want.kind, target)
		}
	}
	return nil
}

// A source, a driver option and a label stay unwritten, since the Compose side of
// them may name a path or a credential the project keeps to itself.
func compareMountSpec(service types.ServiceConfig, origin string, want, got mountSpec) error {
	if want.kind != got.kind {
		return denyf(service.Name, origin,
			"container path %q is a %s mount in compose, found a %s mount", want.target, want.kind, got.kind)
	}
	if want.source != got.source {
		return denyf(service.Name, origin, "container path %q: mount source differs from compose", want.target)
	}
	if want.readOnly != got.readOnly {
		return denyf(service.Name, origin,
			"container path %q is read_only=%t in compose, found %t",
			want.target, want.readOnly, got.readOnly)
	}
	if want.propagation != got.propagation {
		return denyf(service.Name, origin,
			"container path %q declares bind propagation %q in compose, found %q",
			want.target, want.propagation, got.propagation)
	}
	if want.selinux != got.selinux {
		return denyf(service.Name, origin,
			"container path %q declares SELinux relabelling %q in compose, found %q",
			want.target, want.selinux, got.selinux)
	}
	if want.nonRecursive != got.nonRecursive {
		return denyf(service.Name, origin,
			"container path %q: NonRecursive differs (compose: %t, found: %t)",
			want.target, want.nonRecursive, got.nonRecursive)
	}
	if want.readOnlyNonRecursive != got.readOnlyNonRecursive {
		return denyf(service.Name, origin,
			"container path %q: ReadOnlyNonRecursive differs (compose: %t, found: %t)",
			want.target, want.readOnlyNonRecursive, got.readOnlyNonRecursive)
	}
	if want.readOnlyForceRecursive != got.readOnlyForceRecursive {
		return denyf(service.Name, origin,
			"container path %q: ReadOnlyForceRecursive differs (compose: %t, found: %t)",
			want.target, want.readOnlyForceRecursive, got.readOnlyForceRecursive)
	}
	if want.createMountpoint != got.createMountpoint {
		return denyf(service.Name, origin,
			"container path %q declares create_host_path=%t in compose, found %t",
			want.target, want.createMountpoint, got.createMountpoint)
	}
	if want.volumeSubpath != got.volumeSubpath {
		return denyf(service.Name, origin,
			"container path %q declares volume subpath %q in compose, found %q",
			want.target, want.volumeSubpath, got.volumeSubpath)
	}
	if want.volumeNoCopy != got.volumeNoCopy {
		return denyf(service.Name, origin,
			"container path %q declares nocopy=%t in compose, found %t",
			want.target, want.volumeNoCopy, got.volumeNoCopy)
	}
	if want.volumeDriver != got.volumeDriver {
		return denyf(service.Name, origin,
			"container path %q declares volume driver %q in compose, found %q",
			want.target, want.volumeDriver, got.volumeDriver)
	}
	if !maps.Equal(want.volumeDriverOpts, got.volumeDriverOpts) {
		return denyf(service.Name, origin, "container path %q: volume driver options differ from compose", want.target)
	}
	if !maps.Equal(want.volumeLabels, got.volumeLabels) {
		return denyf(service.Name, origin, "container path %q: volume labels differ from compose", want.target)
	}
	if want.imageSubpath != got.imageSubpath {
		return denyf(service.Name, origin,
			"container path %q declares image subpath %q in compose, found %q",
			want.target, want.imageSubpath, got.imageSubpath)
	}
	return nil
}

// expectedMounts reduces the service's volumes to one spec per container path,
// adding the mounts Compose derives from secrets and configs. Sources resolve here.
func expectedMounts(project *types.Project, service types.ServiceConfig) (map[string]mountSpec, error) {
	out := map[string]mountSpec{}

	add := func(spec mountSpec) error {
		if _, dup := out[spec.target]; dup {
			return denyf(service.Name, "volumes",
				"compose declares container path %q twice", spec.target)
		}
		out[spec.target] = spec
		return nil
	}

	for _, v := range service.Volumes {
		spec, err := expectedMountFor(project, v)
		if err != nil {
			return nil, err
		}
		if err := add(spec); err != nil {
			return nil, err
		}
	}

	// A `tmpfs:` entry is not a volume. Compose emits it separately and it has no
	// source.
	for _, raw := range service.Tmpfs {
		target, options, _ := strings.Cut(raw, ":")
		err := add(mountSpec{
			kind:     mountKindTmpfs,
			target:   cleanPath(target),
			readOnly: tmpfsOptionsReadOnly(options),
		})
		if err != nil {
			return nil, err
		}
	}

	// Secrets and configs arrive as read-only binds with no volumes entry of their
	// own, so without this a service using one would see its own mount refused.
	for _, s := range service.Secrets {
		spec, ok, err := expectedSecretMount(project, s)
		if err != nil {
			return nil, err
		}
		if ok {
			if err := add(spec); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range service.Configs {
		spec, ok := expectedConfigMount(project, c)
		if !ok {
			continue
		}
		if err := add(spec); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func expectedMountFor(project *types.Project, v types.ServiceVolumeConfig) (mountSpec, error) {
	spec := mountSpec{target: cleanPath(v.Target), readOnly: v.ReadOnly}

	switch v.Type {
	case types.VolumeTypeBind:
		source, err := compose.BindSource(project, v.Source)
		if err != nil {
			return spec, denyf("", "volumes", "%v", err)
		}
		spec.kind = mountKindBind
		spec.source = source
		if v.Bind != nil {
			spec.propagation = v.Bind.Propagation
			spec.selinux = v.Bind.SELinux
			spec.createMountpoint = bool(v.Bind.CreateHostPath)
			// Compose turns the recursive setting into the three Mount API
			// booleans the daemon understands.
			switch v.Bind.Recursive {
			case "disabled":
				spec.nonRecursive = true
			case "writable":
				spec.readOnlyNonRecursive = true
			case "readonly":
				spec.readOnlyForceRecursive = true
			}
		}
	case types.VolumeTypeVolume:
		spec.kind = mountKindVolume
		if v.Source != "" {
			name, err := compose.VolumeName(project, v.Source)
			if err != nil {
				return spec, denyf("", "volumes", "%v", err)
			}
			spec.source = name
		}
		if v.Volume != nil {
			spec.volumeSubpath = v.Volume.Subpath
			spec.volumeNoCopy = v.Volume.NoCopy
			spec.volumeLabels = map[string]string(v.Volume.Labels)
		}
		// Compose cannot express a per-mount driver, so the expected value is empty
		// and any request that sets one is refused, as HostConfig.StorageOpt gets.
	case types.VolumeTypeTmpfs:
		spec.kind = mountKindTmpfs
	case types.VolumeTypeImage:
		spec.kind = mountKindImage
		// The source is the image reference, and the subpath limits what part of
		// it the container sees.
		spec.source = v.Source
		if v.Image != nil {
			spec.imageSubpath = v.Image.SubPath
		}
	default:
		return spec, denyf("", "volumes",
			"compose declares unsupported volume type %q", v.Type)
	}
	return spec, nil
}

// expectedSecretMount returns the mount Compose derives from a service secret. The
// second result is false when the secret arrives some other way and adds no mount.
func expectedSecretMount(project *types.Project, s types.ServiceSecretConfig) (mountSpec, bool, error) {
	defined, ok := project.Secrets[s.Source]
	if !ok {
		return mountSpec{}, false, denyf("", "secrets",
			"secret %q is not declared in project %q", s.Source, project.Name)
	}
	if defined.Environment != "" {
		return mountSpec{}, false, nil
	}
	target := s.Target
	switch {
	case target == "":
		target = "/run/secrets/" + s.Source
	case !filepath.IsAbs(target):
		target = "/run/secrets/" + target
	}
	return mountSpec{
		kind: mountKindBind,
		// A secret file is mounted without being created.
		target:   cleanPath(target),
		source:   defined.File,
		readOnly: true,
	}, true, nil
}

func expectedConfigMount(project *types.Project, c types.ServiceConfigObjConfig) (mountSpec, bool) {
	defined, ok := project.Configs[c.Source]
	if !ok || bool(defined.External) || defined.Environment != "" || defined.Content != "" {
		return mountSpec{}, false
	}
	target := c.Target
	switch {
	case target == "":
		target = "/" + c.Source
	case !filepath.IsAbs(target):
		target = "/" + target
	}
	return mountSpec{
		kind:             mountKindBind,
		target:           cleanPath(target),
		source:           defined.File,
		readOnly:         true,
		createMountpoint: true,
	}, true
}

func mountSpecFromMount(m mount.Mount) mountSpec {
	spec := mountSpec{
		kind:     mountKind(m.Type),
		target:   cleanPath(m.Target),
		readOnly: m.ReadOnly,
	}
	switch spec.kind {
	case mountKindBind:
		// Only a host path is a path. A volume name and an image reference are
		// stored verbatim, so a name that contains a slash is not rewritten.
		spec.source = cleanPath(m.Source)
	case mountKindVolume, mountKindImage:
		spec.source = m.Source
	}

	if b := m.BindOptions; b != nil {
		spec.propagation = string(b.Propagation)
		spec.nonRecursive = b.NonRecursive
		spec.readOnlyNonRecursive = b.ReadOnlyNonRecursive
		spec.readOnlyForceRecursive = b.ReadOnlyForceRecursive
		spec.createMountpoint = b.CreateMountpoint
	}
	if v := m.VolumeOptions; v != nil {
		spec.volumeSubpath = v.Subpath
		spec.volumeNoCopy = v.NoCopy
		spec.volumeLabels = v.Labels
		if d := v.DriverConfig; d != nil {
			spec.volumeDriver = d.Name
			spec.volumeDriverOpts = d.Options
		}
	}
	if i := m.ImageOptions; i != nil {
		spec.imageSubpath = i.Subpath
	}
	return spec
}

// mountSpecFromBind reduces a legacy Binds entry of the form src:dst:opts. An absolute
// source is a bind and a declared volume name is a named volume.
func mountSpecFromBind(raw string, volumeNames map[string]struct{}) (mountSpec, error) {
	classify := func(src string) mountKind {
		if _, ok := volumeNames[cleanPath(src)]; ok {
			return mountKindVolume
		}
		return mountKindBind
	}

	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		src, dst := parts[0], parts[1]
		kind := classify(src)
		return mountSpec{
			kind:             kind,
			source:           bindOrVolumeSource(kind, src),
			target:           cleanPath(dst),
			createMountpoint: kind == mountKindBind,
		}, nil
	case 1:
		return mountSpec{}, errMalformedBind(raw, "it has no container path")
	default:
		src := strings.Join(parts[:len(parts)-2], ":")
		dst := parts[len(parts)-2]
		opts := strings.Split(parts[len(parts)-1], ",")
		kind := classify(src)
		spec := mountSpec{
			kind:             kind,
			source:           bindOrVolumeSource(kind, src),
			target:           cleanPath(dst),
			createMountpoint: kind == mountKindBind,
		}
		for _, o := range opts {
			switch strings.TrimSpace(o) {
			case "":
			case "ro":
				spec.readOnly = true
			case "rw":
			case "z", "Z":
				spec.selinux = strings.TrimSpace(o)
			case "rshared", "rslave", "rprivate", "runbindable", "rbindable":
				spec.propagation = strings.TrimSpace(o)
			case "nocopy":
				// Compose sends nocopy through the Mount API, but accepting it here
				// too keeps the two representations equivalent.
				spec.volumeNoCopy = true
			default:
				return mountSpec{}, errMalformedBind(raw,
					"mount option "+strconv.Quote(o)+" is one compose never emits")
			}
		}
		return spec, nil
	}
}

func bindOrVolumeSource(kind mountKind, src string) string {
	if kind == mountKindBind {
		return cleanPath(src)
	}
	return src
}

// mountSpecFromTmpfs reduces a HostConfig.Tmpfs map entry. Everything else in
// the option string is class C, so only the read-only flag is kept.
func mountSpecFromTmpfs(path, options string) mountSpec {
	return mountSpec{
		kind:     mountKindTmpfs,
		target:   cleanPath(path),
		readOnly: tmpfsOptionsReadOnly(options),
	}
}

func errMalformedBind(raw, why string) error {
	return fmt.Errorf("bind entry %q is unusable: %s", raw, why)
}

// tmpfsOptionsReadOnly reports whether a tmpfs option string asks for a read-only
// mount, which is the only part of it the policy decides on.
func tmpfsOptionsReadOnly(options string) bool {
	for _, o := range strings.Split(options, ",") {
		if strings.TrimSpace(o) == "ro" {
			return true
		}
	}
	return false
}
