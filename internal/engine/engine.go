// Package engine wraps the Docker client with the read-only operations the proxy
// needs to answer ownership questions about a container or an exec.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/hnw/compose-policy-proxy/internal/policy"
)

type Engine struct {
	client client.APIClient
}

// New connects to the daemon listening on the Unix socket path host.
func New(host string) (*Engine, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", host)
			},
		},
	}
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+host),
		client.WithHTTPClient(httpClient),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	return &Engine{client: cli}, nil
}

func (e *Engine) InspectContainer(ctx context.Context, id string) (container.InspectResponse, error) {
	return e.client.ContainerInspect(ctx, id)
}

func (e *Engine) InspectNetwork(ctx context.Context, id string) (network.Inspect, error) {
	return e.client.NetworkInspect(ctx, id, network.InspectOptions{})
}

// InspectExec reads one exec instance, which is how an exec id is resolved to the
// container it runs in. container.ExecInspect carries neither the container nor the
// privilege the exec was created with, which is the part authorization judges on, so
// the Engine's answer is decoded here. The path carries no API version, because this is
// the proxy's own read of the Engine rather than a request from a client that
// negotiated one.
func (e *Engine) InspectExec(ctx context.Context, id string) (policy.ExecInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/exec/"+id+"/json", nil)
	if err != nil {
		return policy.ExecInfo{}, err
	}
	resp, err := e.client.HTTPClient().Do(req) //nolint:gosec // G704: the Engine socket is the configured upstream
	if err != nil {
		return policy.ExecInfo{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return policy.ExecInfo{}, fmt.Errorf("exec inspect answered %s", resp.Status)
	}

	var answer execInspectAnswer
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return policy.ExecInfo{}, fmt.Errorf("exec inspect answer cannot be decoded: %w", err)
	}
	info := policy.ExecInfo{ContainerID: answer.ContainerID}
	if answer.ProcessConfig != nil {
		info.ProcessConfig = &policy.ExecProcessConfig{
			User:       answer.ProcessConfig.User,
			Privileged: answer.ProcessConfig.Privileged,
			Tty:        answer.ProcessConfig.Tty,
		}
	}
	return info, nil
}

// APIVersions asks the Engine once which API versions it serves, oldest first, so a
// daemon the proxy could not speak to is found at startup rather than on the first request.
func (e *Engine) APIVersions(ctx context.Context) (oldest, newest string, err error) {
	version, err := e.client.ServerVersion(ctx)
	if err != nil {
		return "", "", err
	}
	return version.MinAPIVersion, version.APIVersion, nil
}

// execInspectAnswer is what `GET /exec/{id}/json` reports. The process configuration is
// spelled in lowercase, as the Engine spells it, and a field it omits stays nil rather
// than being read as a zero value.
type execInspectAnswer struct {
	ContainerID   string             `json:"ContainerID"`
	ProcessConfig *execProcessConfig `json:"ProcessConfig"`
}

type execProcessConfig struct {
	User       string `json:"user"`
	Privileged *bool  `json:"privileged"`
	Tty        bool   `json:"tty"`
}
