package policy

import (
	"maps"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/volume"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// volumeIsDeclared reports whether name is one of the volumes this project
// declares, and says nothing about which project owns the Docker volume.
func volumeIsDeclared(project *types.Project, name string) bool {
	for _, resolved := range compose.VolumeNames(project) {
		if resolved == name {
			return true
		}
	}
	return false
}

// matchVolumeCreate compares a volume create request against the Compose
// volume it claims to create, and reports the Compose key it matched.
func matchVolumeCreate(project *types.Project, req volume.CreateOptions) (string, error) {
	var key string
	for candidate, cfg := range project.Volumes {
		if cfg.Name == req.Name {
			key = candidate
			break
		}
	}
	if key == "" {
		return "", denyf("", "Name",
			"volume %q is not declared by compose project %q", req.Name, project.Name)
	}
	cfg := project.Volumes[key]
	if cfg.External {
		return "", denyf("", "Name",
			"volume %q is external and must not be created", req.Name)
	}

	if req.Driver != cfg.Driver {
		return "", denyf("", "Driver",
			"compose declares driver %q for volume %q, request asks for %q", cfg.Driver, req.Name, req.Driver)
	}
	if !maps.Equal(map[string]string(cfg.DriverOpts), req.DriverOpts) {
		return "", denyf("", "DriverOpts",
			"compose declares driver_opts %v for volume %q, request asks for %v", cfg.DriverOpts, req.Name, req.DriverOpts)
	}
	if req.ClusterVolumeSpec != nil {
		return "", denyf("", "ClusterVolumeSpec", "compose never creates a cluster volume")
	}

	wantLabels := copyLabels(cfg.Labels)
	wantLabels[LabelProject] = project.Name
	wantLabels[LabelVolume] = key
	if !hasLabel(wantLabels, req.Labels) {
		return "", denyf("", "Labels",
			"volume %q is missing the compose project management label %s=%s", req.Name, LabelProject, project.Name)
	}
	return key, nil
}
