package compose

import (
	"fmt"
	"path/filepath"

	"github.com/compose-spec/compose-go/v2/types"
)

const DefaultNetworkKey = "default"

// Services returns every declared service, including profile gated ones, because the
// proxy selects no profile and a reachable service still has to be describable.
func Services(project *types.Project) types.Services {
	return project.AllServices()
}

func Service(project *types.Project, name string) (types.ServiceConfig, error) {
	for _, s := range project.AllServices() {
		if s.Name == name {
			return s, nil
		}
	}
	return types.ServiceConfig{}, fmt.Errorf("service %q is not declared in project %q", name, project.Name)
}

func NetworkNames(project *types.Project) map[string]string {
	names := make(map[string]string, len(project.Networks))
	for key, cfg := range project.Networks {
		names[key] = cfg.Name
	}
	return names
}

// NetworkKey is the Compose key of the network a Docker name resolves to.
func NetworkKey(project *types.Project, name string) (string, bool) {
	for key, cfg := range project.Networks {
		if cfg.Name == name {
			return key, true
		}
	}
	return "", false
}

func VolumeNames(project *types.Project) map[string]string {
	names := make(map[string]string, len(project.Volumes))
	for key, cfg := range project.Volumes {
		names[key] = cfg.Name
	}
	return names
}

func NetworkName(project *types.Project, key string) (string, error) {
	cfg, ok := project.Networks[key]
	if !ok {
		return "", fmt.Errorf("network %q is not declared in project %q", key, project.Name)
	}
	if cfg.Name == "" {
		return "", fmt.Errorf("network %q in project %q has no resolved name", key, project.Name)
	}
	return cfg.Name, nil
}

func VolumeName(project *types.Project, key string) (string, error) {
	cfg, ok := project.Volumes[key]
	if !ok {
		return "", fmt.Errorf("volume %q is not declared in project %q", key, project.Name)
	}
	if cfg.Name == "" {
		return "", fmt.Errorf("volume %q in project %q has no resolved name", key, project.Name)
	}
	return cfg.Name, nil
}

// A relative source resolves against the project working directory, which must exist
// at the same absolute path on the Docker host. Symlinks are left unresolved, as Compose does.
func BindSource(project *types.Project, source string) (string, error) {
	if source == "" {
		return "", fmt.Errorf("empty bind mount source")
	}
	if filepath.IsAbs(source) {
		return filepath.Clean(source), nil
	}
	wd, err := filepath.Abs(project.WorkingDir)
	if err != nil {
		return "", fmt.Errorf("resolve project working directory: %w", err)
	}
	return filepath.Clean(filepath.Join(wd, source)), nil
}

func ImageName(project *types.Project, service types.ServiceConfig) string {
	if service.Image != "" {
		return service.Image
	}
	return project.Name + Separator + service.Name
}
