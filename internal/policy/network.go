package policy

import (
	"maps"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/network"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// networkIsDeclared reports whether name is one of the networks this project
// declares, managed or external, and says nothing about which project owns it.
func networkIsDeclared(project *types.Project, name string) bool {
	for _, resolved := range compose.NetworkNames(project) {
		if resolved == name {
			return true
		}
	}
	return false
}

// matchNetworkCreate compares a network create request against the Compose
// network it claims to create, and reports the Compose key it matched.
func matchNetworkCreate(project *types.Project, req network.CreateRequest) (string, error) {
	var key string
	for candidate, cfg := range project.Networks {
		if cfg.Name == req.Name {
			key = candidate
			break
		}
	}
	if key == "" {
		return "", denyf("", "Name",
			"network %q is not declared by compose project %q", req.Name, project.Name)
	}
	cfg := project.Networks[key]
	if cfg.External {
		return "", denyf("", "Name",
			"network %q is external and must not be created", req.Name)
	}

	opts := req.CreateOptions

	if req.Driver != cfg.Driver {
		return "", denyf("", "Driver",
			"compose declares driver %q for network %q, request asks for %q", cfg.Driver, req.Name, req.Driver)
	}
	if !maps.Equal(map[string]string(cfg.DriverOpts), opts.Options) {
		return "", denyf("", "Options",
			"compose declares driver_opts %v for network %q, request asks for %v", cfg.DriverOpts, req.Name, opts.Options)
	}
	if opts.Internal != cfg.Internal {
		return "", denyf("", "Internal",
			"compose sets internal=%t for network %q, request asks for %t", cfg.Internal, req.Name, opts.Internal)
	}
	if opts.Attachable != cfg.Attachable {
		return "", denyf("", "Attachable",
			"compose sets attachable=%t for network %q, request asks for %t", cfg.Attachable, req.Name, opts.Attachable)
	}
	if opts.Ingress {
		return "", denyf("", "Ingress", "compose never creates an ingress network")
	}
	if opts.ConfigOnly {
		return "", denyf("", "ConfigOnly", "compose never creates a config-only network")
	}
	if opts.ConfigFrom != nil {
		return "", denyf("", "ConfigFrom",
			"compose never attaches a container to a config-only network")
	}
	if opts.Scope != "" && opts.Scope != "local" && opts.Scope != "swarm" {
		return "", denyf("", "Scope",
			"compose does not declare network scope %q", opts.Scope)
	}
	if cfg.EnableIPv4 != nil && boolValue(opts.EnableIPv4) != *cfg.EnableIPv4 {
		return "", denyf("", "EnableIPv4",
			"compose sets enable_ipv4=%t for network %q, request asks for %t", *cfg.EnableIPv4, req.Name, boolValue(opts.EnableIPv4))
	}
	if cfg.EnableIPv6 != nil && boolValue(opts.EnableIPv6) != *cfg.EnableIPv6 {
		return "", denyf("", "EnableIPv6",
			"compose sets enable_ipv6=%t for network %q, request asks for %t", *cfg.EnableIPv6, req.Name, boolValue(opts.EnableIPv6))
	}

	// Compose adds management labels of its own, and the config hash and client
	// version differ per run, so only the labels tying the resource to a project count.
	wantLabels := copyLabels(cfg.Labels)
	wantLabels[LabelProject] = project.Name
	wantLabels[LabelNetwork] = key
	if !hasLabel(wantLabels, opts.Labels) {
		return "", denyf("", "Labels",
			"network %q is missing the compose project management label %s=%s", req.Name, LabelProject, project.Name)
	}

	if err := compareIPAM(cfg.Ipam, opts.IPAM, req.Name); err != nil {
		return "", err
	}
	return key, nil
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// builtinIPAMDriver is the IPAM driver every Engine registers itself, under this
// name. The Docker API types do not name it.
const builtinIPAMDriver = "default"

func compareIPAM(want types.IPAMConfig, got *network.IPAM, name string) error {
	if len(want.Config) == 0 && len(want.Options) == 0 && want.Driver == "" {
		if got == nil {
			return nil
		}
		if len(got.Config) != 0 {
			return denyf("", "IPAM",
				"compose declares no IPAM for network %q, request asks for %+v", name, got)
		}
		// Compose sends no IPAM at all for such a network, so a driver or option
		// here was the client's choice of a plugin. An empty driver is the built-in one.
		if got.Driver != "" && got.Driver != builtinIPAMDriver {
			return denyf("", "IPAM.Driver",
				"compose declares no IPAM driver for network %q, request asks for %q", name, got.Driver)
		}
		if len(got.Options) != 0 {
			return denyf("", "IPAM.Options",
				"compose declares no IPAM options for network %q, request asks for %v", name, got.Options)
		}
		return nil
	}
	if got == nil {
		return denyf("", "IPAM",
			"compose declares IPAM for network %q, request asks for none", name)
	}
	if got.Driver != want.Driver {
		return denyf("", "IPAM.Driver",
			"compose declares ipam driver %q for network %q, request asks for %q", want.Driver, name, got.Driver)
	}
	if !maps.Equal(map[string]string(want.Options), got.Options) {
		return denyf("", "IPAM.Options",
			"compose declares ipam options %v for network %q, request asks for %v", want.Options, name, got.Options)
	}
	if len(got.Config) != len(want.Config) {
		return denyf("", "IPAM.Config",
			"compose declares %d IPAM pools for network %q, request asks for %d", len(want.Config), name, len(got.Config))
	}
	for i, pool := range want.Config {
		gotPool := got.Config[i]
		if !sameIP(pool.Subnet, gotPool.Subnet) {
			return denyf("", "IPAM.Config.Subnet",
				"compose declares subnet %q for network %q, request asks for %q", pool.Subnet, name, gotPool.Subnet)
		}
		if !sameIP(pool.Gateway, gotPool.Gateway) {
			return denyf("", "IPAM.Config.Gateway",
				"compose declares gateway %q for network %q, request asks for %q", pool.Gateway, name, gotPool.Gateway)
		}
		if !sameIP(pool.IPRange, gotPool.IPRange) {
			return denyf("", "IPAM.Config.IPRange",
				"compose declares ip_range %q for network %q, request asks for %q", pool.IPRange, name, gotPool.IPRange)
		}
		if !maps.Equal(map[string]string(pool.AuxiliaryAddresses), gotPool.AuxAddress) {
			return denyf("", "IPAM.Config.AuxiliaryAddresses",
				"compose declares aux_addresses %v for network %q, request asks for %v", pool.AuxiliaryAddresses, name, gotPool.AuxAddress)
		}
	}
	return nil
}

func hasLabel(required, got map[string]string) bool {
	for k, v := range required {
		if gv, ok := got[k]; !ok || gv != v {
			return false
		}
	}
	return true
}
