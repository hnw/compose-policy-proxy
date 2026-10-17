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
	// Engine is read to establish ownership of containers that already exist, and of
	// the exec instances running in them. Nothing in this package forwards a request
	// to it.
	Engine EngineInspector
	// AllowedCommands is the set of Compose commands to authorize, as parsed by
	// ParseCommands. An empty set authorizes no command at all.
	AllowedCommands Commands
}

// EngineInspector is the read-only part of the Engine that authorization needs: a
// container, whose ownership is established from what the Engine reports, and an exec
// instance, which names no container at all. It is the only Engine access authorization
// needs, and it decides nothing on its own.
type EngineInspector interface {
	InspectContainer(ctx context.Context, id string) (container.InspectResponse, error)
	InspectExec(ctx context.Context, id string) (ExecInfo, error)
}

// Policy authorizes Docker API requests for one Compose project. It is safe for
// concurrent use, as no decision state is cached between requests.
type Policy struct {
	project   *types.Project
	protected protectedServices
	inspect   EngineInspector
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

	case "/containers/{id}/exec":
		service, err := p.authorizeExecCreate(ctx, op, req)
		return service, "", "", err

	case "/exec/{id}/json", "/exec/{id}/start", "/exec/{id}/resize":
		service, err := p.authorizeExec(ctx, op, req)
		return service, "", "", err

	case "/images/create":
		// A pull is what `docker compose pull` performs, and what `run` needs before
		// it can create anything, so either command authorizes it.
		if err := p.commands.checkAny(commandPull, commandRun); err != nil {
			return "", "", "", err
		}
		return "", "", "", authorizePull(p.project, query)

	case "/images/{name}/json":
		if !imageDeclared(p.project, op.Target) {
			return "", "", "", denyf("", "",
				"image %q is not declared by compose project %q", op.Target, p.project.Name)
		}
		return "", "", "", nil

	case "/events":
		// The event watch a followed log stream opens, so it belongs to `logs` and
		// observes the project's own containers only.
		if err := p.commands.check(commandLogs); err != nil {
			return "", "", "", err
		}
		filters, err := checkEventScope(p.project, query.Get("filters"))
		return "", "", filters, err

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
	service, insp, err := p.ownContainer(ctx, op.Target, op.Endpoint, method)
	if err != nil {
		return "", err
	}
	if isReadOnlyOperation(op.Endpoint, method) {
		return service, nil
	}
	return service, p.checkControl(op, insp.Config.Labels)
}

// ownContainer settles which service an existing container belongs to and whether the
// endpoint may act on it at all, which is what the protected rule decides. Everything
// it reads comes from the Engine, never from the request.
func (p *Policy) ownContainer(ctx context.Context, id, endpoint, method string) (string, container.InspectResponse, error) {
	if id == "" {
		return "", container.InspectResponse{}, deny("", "", "container id is empty")
	}
	insp, err := p.inspect.InspectContainer(ctx, id)
	if err != nil {
		return "", container.InspectResponse{}, deny("", "", "container is not accessible through this proxy")
	}
	// Ownership first, so that the protected check can only narrow a decision
	// already made from the container itself rather than from a client label.
	service, err := p.matchExistingContainer(insp)
	if err != nil {
		return "", container.InspectResponse{}, err
	}
	if err := p.protected.checkContainerOperation(service, endpoint, method); err != nil {
		return "", container.InspectResponse{}, err
	}
	return service, insp, nil
}

// checkControl decides what may be done to a container whose ownership is established.
// A one-off container belongs to `run`; an ordinary one belongs to the command that
// acts on it, and to no other.
func (p *Policy) checkControl(op operation, labels map[string]string) error {
	// Logs return what the container wrote, so `run` on a one-off container says
	// nothing about them; only `logs` does, whichever kind of container it is.
	if op.Endpoint == logsEndpoint {
		return p.commands.check(commandLogs)
	}
	if isOneOff(labels) {
		return p.commands.check(commandRun)
	}
	if command, ok := serviceContainerOperations[op.Endpoint]; ok {
		return p.commands.check(command)
	}
	return deny("", "", "this operation is not allowed for a service container")
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
