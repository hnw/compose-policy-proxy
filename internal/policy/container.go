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
	LabelOneoff  = "com.docker.compose.oneoff"
	LabelNetwork = "com.docker.compose.network"
	LabelVolume  = "com.docker.compose.volume"
)

// oneoffLabelValue is what Compose writes for a one-off container.
const oneoffLabelValue = "True"

// matchCreate reports which service a create request matches. The Compose labels
// name that service, so they are required rather than a hint.
func (p *Policy) matchCreate(req *container.CreateRequest) (string, error) {
	if req.Config == nil {
		return "", deny("", "request", "container config is empty")
	}
	project := p.project
	if got := req.Labels[LabelProject]; got != project.Name {
		return "", denyf("", LabelProject,
			"request claims project %q, this proxy serves project %q", got, project.Name)
	}
	if err := checkOneOff(req.Labels); err != nil {
		return "", err
	}
	serviceName := req.Labels[LabelService]
	service, err := compose.Service(project, serviceName)
	if err != nil {
		return "", denyf("", LabelService,
			"request names service %q, which project %q does not declare", serviceName, project.Name)
	}
	if err := compareService(project, service, req, modeCreate); err != nil {
		return "", err
	}
	if err := p.protected.checkCreate(service.Name); err != nil {
		return "", err
	}
	return service.Name, nil
}

// checkOneOff requires the label Compose sets for a one-off container. A client
// chooses its own labels, so the label narrows what this proxy serves rather
// than proving where the request came from.
func checkOneOff(labels map[string]string) error {
	if !isOneOff(labels) {
		return denyf("", LabelOneoff,
			"only one-off containers are allowed (expected %q, found %q)",
			oneoffLabelValue, labels[LabelOneoff])
	}
	return nil
}

func isOneOff(labels map[string]string) bool {
	return labels[LabelOneoff] == oneoffLabelValue
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
