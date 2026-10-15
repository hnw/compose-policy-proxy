package policy

import (
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// Compose management labels the policy reads. Every other label Compose writes
// carries no authority here, so it is neither trusted nor named.
const (
	LabelProject = "com.docker.compose.project"
	LabelService = "com.docker.compose.service"
	LabelNetwork = "com.docker.compose.network"
	LabelVolume  = "com.docker.compose.volume"
)

// matchCreate reports which service a create request matches. The Compose labels
// in the request only order the candidates, so every service is tried.
func (p *Policy) matchCreate(req *container.CreateRequest) (string, error) {
	if req.Config == nil {
		return "", deny("", "request", "container config is empty")
	}
	project := p.project
	hint := req.Labels[LabelService]
	candidates := candidateServices(project, hint)
	if len(candidates) == 0 {
		return "", deny("", "service", "project "+project.Name+" declares no service")
	}

	// A refusal names the service the request pointed at, or the only one using
	// its image, since a field of an unrelated service would mislead.
	var hintErr, imageErr error
	imageUses := 0
	for _, service := range candidates {
		err := compareService(project, service, req, modeCreate)
		if err == nil {
			if err := p.protected.checkCreate(service.Name); err != nil {
				return "", err
			}
			return service.Name, nil
		}
		if service.Name == hint {
			hintErr = err
		}
		if compose.ImageName(project, service) == req.Config.Image {
			imageUses++
			imageErr = err
		}
	}
	switch {
	case hintErr != nil:
		return "", hintErr
	case imageUses == 1:
		return "", imageErr
	case imageUses == 0:
		return "", denyf("", "", "no Compose service matches image %q", req.Config.Image)
	}
	return "", deny("", "", "no Compose service matches this request")
}

// candidateServices orders services so the one named by the request label is
// tried first.
func candidateServices(project *types.Project, hint string) []types.ServiceConfig {
	all := compose.Services(project)
	out := make([]types.ServiceConfig, 0, len(all))
	if hint != "" {
		if s, err := compose.Service(project, hint); err == nil {
			out = append(out, s)
		}
	}
	for _, s := range all {
		if s.Name == hint {
			continue
		}
		out = append(out, s)
	}
	return out
}

// matchExistingContainer requires the project label and matching security state, since
// neither alone is ownership. It reads the Engine, so a restart forgets nothing.
func (p *Policy) matchExistingContainer(insp container.InspectResponse) (string, error) {
	if insp.Config == nil {
		return "", deny("", "container", "inspect result has no config")
	}
	if got := insp.Config.Labels[LabelProject]; got != p.project.Name {
		return "", denyf("", LabelProject,
			"container belongs to project %q, this proxy serves project %q", got, p.project.Name)
	}
	serviceName := insp.Config.Labels[LabelService]
	service, err := compose.Service(p.project, serviceName)
	if err != nil {
		return "", denyf("", LabelService,
			"container names service %q, which project %q does not declare", serviceName, p.project.Name)
	}
	if err := p.compareContainer(service, insp); err != nil {
		return "", err
	}
	return service.Name, nil
}

// compareContainer reuses the create policy in inspect mode.
func (p *Policy) compareContainer(
	service types.ServiceConfig,
	insp container.InspectResponse,
) error {
	return compareService(p.project, service, requestFromInspect(insp), modeInspect)
}

// requestFromInspect renders an inspect result as a create request. Fields the
// daemon owns are not blanked, because a blank would be compared against Compose.
func requestFromInspect(insp container.InspectResponse) *container.CreateRequest {
	cfg := insp.Config
	if cfg == nil {
		cfg = &container.Config{}
	}
	host := &container.HostConfig{}
	if insp.HostConfig != nil {
		*host = *insp.HostConfig
	}

	netConf := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{}}
	if insp.NetworkSettings != nil {
		for name, ep := range insp.NetworkSettings.Networks {
			if ep == nil {
				netConf.EndpointsConfig[name] = &network.EndpointSettings{}
				continue
			}
			cp := *ep
			// Operational values assigned by the daemon, not requested values.
			cp.NetworkID = ""
			cp.EndpointID = ""
			cp.Gateway = ""
			cp.IPPrefixLen = 0
			cp.IPv6Gateway = ""
			cp.GlobalIPv6Address = ""
			cp.GlobalIPv6PrefixLen = 0
			cp.DNSNames = nil
			netConf.EndpointsConfig[name] = &cp
		}
	}

	return &container.CreateRequest{
		Config:           cfg,
		HostConfig:       host,
		NetworkingConfig: netConf,
	}
}
