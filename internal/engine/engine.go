// Package engine wraps the Docker client with the read-only operations the proxy
// needs to answer ownership questions.
package engine

import (
	"context"
	"net"
	"net/http"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
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

// APIVersions asks the Engine once which API versions it serves, oldest first, so a
// daemon the proxy could not speak to is found at startup rather than on the first request.
func (e *Engine) APIVersions(ctx context.Context) (oldest, newest string, err error) {
	version, err := e.client.ServerVersion(ctx)
	if err != nil {
		return "", "", err
	}
	return version.MinAPIVersion, version.APIVersion, nil
}
