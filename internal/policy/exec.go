package policy

import (
	"context"

	"github.com/docker/docker/api/types/container"
)

// ExecInfo is what the Engine reports about one exec instance. ProcessConfig is a
// pointer because an answer without it cannot be judged on, which is not the same as
// an answer reporting that the exec asked for no privilege.
type ExecInfo struct {
	ContainerID   string
	ProcessConfig *ExecProcessConfig
}

// ExecProcessConfig is the privilege an exec instance was created with, as the Engine
// reports it back; the Moby type for an exec inspect carries none of it. User is the
// user the exec will actually run as, which is the container's own user when the create
// request left it empty.
type ExecProcessConfig struct {
	User string
	// Privileged is a pointer so that an answer omitting the field is not read as a
	// request without privilege.
	Privileged *bool
	Tty        bool
}

const execStartEndpoint = "/exec/{id}/start"

// authorizeExecCreate settles an exec a client asks to create inside a container the
// proxy has established as its own. The command, environment and working directory are
// the client's, as they are for `run`: an exec runs with the container's own namespaces
// and capabilities, so the only privilege it may add is none of its own.
func (p *Policy) authorizeExecCreate(ctx context.Context, op operation, req *Request) (string, error) {
	var create container.ExecOptions
	if err := decodeRequest(req.Body, "exec create request", &create); err != nil {
		return "", err
	}
	service, _, err := p.ownContainer(ctx, op.Target, op.Endpoint, req.Method)
	if err != nil {
		return "", err
	}
	if err := p.commands.check(commandExec); err != nil {
		return service, err
	}
	if create.Privileged {
		return service, deny(service, "Privileged", "an exec may not be privileged")
	}
	if create.User != "" {
		return service, deny(service, "User", "an exec may not run as a user of its own")
	}
	return service, nil
}

// authorizeExec settles an operation on an exec the Engine already holds. An exec id
// names no container, so the Engine's own answer is the only link to one, and an answer
// the proxy cannot read settles nothing.
func (p *Policy) authorizeExec(ctx context.Context, op operation, req *Request) (string, error) {
	info, err := p.inspect.InspectExec(ctx, op.Target)
	if err != nil {
		return "", deny("", "", "the exec instance cannot be read through this proxy")
	}
	service, insp, err := p.ownContainer(ctx, info.ContainerID, op.Endpoint, req.Method)
	if err != nil {
		return "", err
	}
	if isReadOnlyOperation(op.Endpoint, req.Method) {
		return service, nil
	}
	if err := p.commands.check(commandExec); err != nil {
		return service, err
	}
	process := info.ProcessConfig
	if process == nil {
		return service, deny(service, "",
			"the Engine reports no process configuration for this exec, so it cannot be judged")
	}
	if process.Privileged == nil || *process.Privileged {
		return service, deny(service, "Privileged", "an exec may not be privileged")
	}
	if process.User != insp.Config.User {
		return service, deny(service, "User", "an exec may not run as a user other than the container's")
	}
	if op.Endpoint != execStartEndpoint {
		return service, nil
	}

	// The Engine frames the stream by the terminal the start names rather than by the
	// one the exec has, so a start that disagrees reads as a shape the client never asked for.
	var start container.ExecStartOptions
	if err := decodeRequest(req.Body, "exec start request", &start); err != nil {
		return service, err
	}
	if start.Tty != process.Tty {
		return service, deny(service, "Tty",
			"an exec may only be started with the terminal it was created with")
	}
	return service, nil
}
