// Package policy authorizes Docker API requests against a resolved Compose
// project, including container ownership and protected services.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
)

// MaxBodySize bounds the request body the proxy buffers to decide on it. A larger
// body is refused rather than partially compared.
const MaxBodySize = 8 << 20

// Config is what an authorization policy is built from.
type Config struct {
	// Project is a startup-time snapshot of the resolved Compose project, treated
	// as immutable, so changing the Compose configuration means restarting the proxy.
	Project *types.Project
	// DockerHost is the daemon socket a service would mount to reach the Engine
	// without the proxy. A service doing so is protected.
	DockerHost string
	// Listen is the proxy's own restricted socket. A service holding it reaches
	// the Engine only through the proxy, so it is not protected.
	Listen string
	// Engine is read to establish ownership of containers that already exist.
	// Nothing in this package forwards a request to it.
	Engine ContainerInspector
	// AllowedCommands is the set of Compose commands to authorize, as parsed by
	// ParseCommands. An empty set authorizes no command at all.
	AllowedCommands Commands
}

// ContainerInspector reads a container so that its ownership can be established.
// It is the only Engine operation authorization needs.
type ContainerInspector interface {
	InspectContainer(ctx context.Context, id string) (container.InspectResponse, error)
}

// Policy authorizes Docker API requests for one Compose project. It is safe for
// concurrent use, as no decision state is cached between requests.
type Policy struct {
	project   *types.Project
	protected protectedServices
	inspect   ContainerInspector
	commands  Commands
}

// New builds a Policy. The protected services and seccomp profiles are resolved
// here, once, so no decision reads the file system later.
func New(cfg Config) (*Policy, error) {
	project, err := resolveSeccompProfiles(cfg.Project)
	if err != nil {
		return nil, err
	}
	return &Policy{
		project:   project,
		protected: resolveProtectedServices(project, cfg.DockerHost, cfg.Listen),
		inspect:   cfg.Engine,
		commands:  cfg.AllowedCommands,
	}, nil
}

// ProtectedServices returns the names of the protected services, in a stable
// order, for logging at startup.
func (p *Policy) ProtectedServices() []string {
	return p.protected.names()
}

// Request is a Docker API request to authorize. The policy reads it and does not
// modify it.
type Request struct {
	Method string
	// URL is the request URL as it arrived, API version prefix and query included.
	// The daemon gets the same one, so the version is judged as received.
	URL *url.URL
	// Body is the request body, already read from the connection.
	Body []byte
}

// Decision is what an authorized request was matched against. The proxy records it
// and decides how to forward it, and it carries no authority of its own.
type Decision struct {
	// Endpoint is the allowlist path that matched, without the API version
	// prefix, so that a decision reads the same across API versions.
	Endpoint string
	Target   string
	Service  string
	// Resource is the Compose key a network or volume create matched. It is not a
	// service name, so it is recorded apart from one.
	Resource string
	// Filters is the `filters` query the proxy forwards instead of the client's,
	// to pin a list to the authorized resources. The Engine reads a name filter as a regex.
	Filters string
}

// Authorize decides whether a Docker API request may be forwarded exactly as it
// arrived. Any error is a refusal, and the Decision names as much as was understood.
func (p *Policy) Authorize(ctx context.Context, req *Request) (Decision, error) {
	op, err := resolve(req.URL.Path)
	if err != nil {
		return Decision{}, err
	}
	decision := Decision{Endpoint: op.Endpoint, Target: op.Target}
	if err := op.checkVersion(); err != nil {
		return decision, err
	}
	if err := op.checkMethod(req.Method); err != nil {
		return decision, err
	}

	decision.Service, decision.Resource, decision.Filters, err = p.decide(ctx, op, req)
	return decision, err
}

// decide applies the rules that depend on what the request addresses. The
// endpoint has already been resolved, version checked and method checked.
func (p *Policy) decide(ctx context.Context, op operation, req *Request) (service, resource, filters string, err error) {
	query := req.URL.Query()

	// The operations only `run` performs are authorized before the request is
	// interpreted, since nothing about their body changes what they are.
	if runOnlyOperations[op.Endpoint] {
		if err := p.commands.check(commandRun); err != nil {
			return "", "", "", err
		}
	}

	switch op.Endpoint {
	case "/_ping", "/version", "/info":
		// API negotiation. No resource is addressed, so there is nothing left to
		// authorize once the path, version and method have been checked.
		return "", "", "", nil

	case "/containers/create":
		var create container.CreateRequest
		if err := decodeRequest(req.Body, "container create request", &create); err != nil {
			return "", "", "", err
		}
		service, err := p.matchCreate(&create)
		return service, "", "", err

	case "/containers/json":
		filters, err := p.checkListScope(kindContainer, query.Get("filters"))
		return "", "", filters, err

	case "/images/create":
		return "", "", "", authorizePull(p.project, query)

	case "/images/{name}/json":
		if !imageDeclared(p.project, op.Target) {
			return "", "", "", denyf("", "",
				"image %q is not declared by compose project %q", op.Target, p.project.Name)
		}
		return "", "", "", nil

	case "/networks":
		filters, err := p.checkListScope(kindNetwork, query.Get("filters"))
		return "", "", filters, err

	case "/networks/create":
		var create network.CreateRequest
		if err := decodeRequest(req.Body, "network create request", &create); err != nil {
			return "", "", "", err
		}
		key, err := matchNetworkCreate(p.project, create)
		return "", key, "", err

	case "/volumes":
		filters, err := p.checkListScope(kindVolume, query.Get("filters"))
		return "", "", filters, err

	case "/volumes/create":
		var create volume.CreateOptions
		if err := decodeRequest(req.Body, "volume create request", &create); err != nil {
			return "", "", "", err
		}
		key, err := matchVolumeCreate(p.project, create)
		return "", key, "", err
	}

	// Everything left names one resource. A container must be inspected before it
	// can be acted on at all, a network and a volume are matched by name.
	switch {
	case strings.HasPrefix(op.Endpoint, "/containers/"):
		service, err := p.authorizeContainer(ctx, op, req.Method)
		return service, "", "", err
	case strings.HasPrefix(op.Endpoint, "/networks/"):
		if !networkIsDeclared(p.project, op.Target) {
			return "", "", "", denyf("", "",
				"network %q is not declared by compose project %q", op.Target, p.project.Name)
		}
		return "", "", "", nil
	case strings.HasPrefix(op.Endpoint, "/volumes/"):
		if !volumeIsDeclared(p.project, op.Target) {
			return "", "", "", denyf("", "",
				"volume %q is not declared by compose project %q", op.Target, p.project.Name)
		}
		return "", "", "", nil
	}

	// An allowlisted endpoint with no rule above is refused, because joining the
	// allowlist must not authorize an operation by itself.
	return "", "", "", errUnhandledEndpoint
}

// authorizeContainer settles ownership of an existing container and then whether
// the operation may act on it.
func (p *Policy) authorizeContainer(ctx context.Context, op operation, method string) (string, error) {
	if op.Target == "" {
		return "", deny("", "", "container id is empty")
	}
	insp, err := p.inspect.InspectContainer(ctx, op.Target)
	if err != nil {
		return "", denyf("", "",
			"container %q cannot be inspected, so its ownership cannot be established", op.Target)
	}
	// Ownership first, so that the protected check can only narrow a decision
	// already made from the container itself rather than from a client label.
	service, err := p.matchExistingContainer(insp)
	if err != nil {
		return "", err
	}
	if err := p.protected.checkContainerOperation(service, op.Endpoint, method); err != nil {
		return "", err
	}
	if isReadOnlyOperation(op.Endpoint, method) {
		return service, nil
	}
	return service, p.checkControl(op, insp.Config.Labels)
}

// checkControl decides what may be done to a container whose ownership is established.
// A one-off container belongs to `run`; an ordinary one belongs to the command that
// acts on it, and to no other.
func (p *Policy) checkControl(op operation, labels map[string]string) error {
	if isOneOff(labels) {
		return p.commands.check(commandRun)
	}
	if command, ok := serviceContainerOperations[op.Endpoint]; ok {
		return p.commands.check(command)
	}
	return checkOneOff(labels)
}

// decodeRequest refuses any field the Moby types do not know, since Go would
// otherwise forward a new security-sensitive field unseen and a Moby bump would pass review.
func decodeRequest(body []byte, what string, target any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return Malformed("%s cannot be decoded: %v", what, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Malformed("%s cannot be decoded: request body carries trailing content", what)
	}
	return nil
}
