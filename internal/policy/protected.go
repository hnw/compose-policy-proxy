package policy

import (
	"path/filepath"
	"slices"

	"github.com/compose-spec/compose-go/v2/types"

	"github.com/hnw/compose-policy-proxy/internal/compose"
)

// protectedServices is the set of services holding the Docker socket themselves. Field
// comparison cannot express the rule, since such a request matches Compose exactly.
type protectedServices map[string]struct{}

// resolveProtectedServices identifies services with direct upstream socket access, using
// the same mounts as create time so both agree. See docs/security-model.md.
func resolveProtectedServices(project *types.Project, dockerHost, restrictedSocket string) protectedServices {
	upstream := filepath.Clean(dockerHost)
	restricted := filepath.Clean(restrictedSocket)

	protected := protectedServices{}
	for _, service := range compose.Services(project) {
		mounts, err := expectedMounts(project, service)
		if err != nil {
			// Nothing can be shown about mounts that do not resolve, so the
			// service is protected. The comparison refuses its create first.
			protected[service.Name] = struct{}{}
			continue
		}
		if mountsUpstreamSocket(mounts, upstream, restricted) {
			protected[service.Name] = struct{}{}
		}
	}
	return protected
}

func mountsUpstreamSocket(mounts map[string]mountSpec, upstream, restricted string) bool {
	for target, spec := range mounts {
		if spec.kind != mountKindBind || cleanPath(target) != upstream {
			continue
		}
		if cleanPath(spec.source) != restricted {
			return true
		}
	}
	return false
}

func (p protectedServices) isProtected(service string) bool {
	_, ok := p[service]
	return ok
}

// checkCreate refuses a service holding the Docker socket this proxy guards. It runs
// after a full match, so a field mismatch is still reported as the field that differs.
func (p protectedServices) checkCreate(service string) error {
	if !p.isProtected(service) {
		return nil
	}
	return deny(service, "",
		"container creation is not allowed for a protected service")
}

// checkContainerOperation allows observation and refuses control on a protected service's
// container. The name comes from the Engine inspect result, never from a client label.
func (p protectedServices) checkContainerOperation(service, endpoint, method string) error {
	if !p.isProtected(service) || isReadOnlyOperation(endpoint, method) {
		return nil
	}
	return denyf(service, "",
		"%s %s is not allowed for a protected service", method, endpoint)
}

func (p protectedServices) names() []string {
	out := make([]string, 0, len(p))
	for name := range p {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
