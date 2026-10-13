# Quick start example

This example demonstrates Docker-outside-of-Docker (DooD) with restricted Docker access.

The `app` container represents a CI runner or bot. It can launch sibling containers using Docker Compose, but all Docker API requests go through `compose-policy-proxy`.

## Services

| Service | Role |
| --- | --- |
| `policy-proxy` | Restricts Docker API access using `compose.yaml` |
| `app` | Runs Docker Compose through the restricted socket |
| `tool` | A predefined service that `app` can launch |

The host starts `policy-proxy` and `app`. The `tool` service is launched on demand from inside `app`.

## Run it

From this directory, on the host:

```console
docker compose up -d --build
docker compose exec app sh
```

You are now inside the `app` container.

This container has Docker CLI and the Compose plugin, but its `DOCKER_HOST` points to the restricted socket rather than the host Docker socket.

Run a tool:

```console
docker compose run --rm tool echo "hello through the proxy"
```

Expected output:

```text
hello through the proxy
```

Docker Compose creates a one-off container from the `tool` service definition. The proxy checks the request against `compose.yaml` before forwarding it to the host Docker Engine.

The new container is a sibling of `app`, not a container running inside it.

## Try a denied request

Still inside `app`, try enabling privileged mode:

```console
docker compose run --rm --cap-add SYS_ADMIN tool true
```

The proxy refuses the request because `cap_add: [SYS_ADMIN]` is not permitted by the `tool` service definition.

You can also try running an image that is not declared in the Compose project:

```console
docker run --rm busybox true
```

The proxy will not authorize an arbitrary container just because the client can access its Docker socket.

## Inspect the logs

Exit `app`:

```console
exit
```

Then, on the host:

```console
docker compose logs policy-proxy
```

The logs show allowed and denied requests, including the matched service and denial reasons.

Clean up with:

```console
docker compose down
```

## How it works

The host starts two long-running services:

- `policy-proxy` receives the host Docker socket.
- `app` receives only the restricted socket through the shared `proxy-socket` volume.

Both use the same Compose project. The proxy reads its configuration and uses the declared services as the policy for Docker API requests.

The `tool` service has the `tools` profile, so it is not started by the host's `docker compose up -d`. It can still be launched explicitly using `docker compose run tool`.

The `app` image is built from `app.Dockerfile`, which adds the Compose plugin to the Docker CLI image. The proxy itself uses a prebuilt image from GHCR.

In a real deployment, replace `app` with your CI runner, bot, or automation service, and define the containerized tools it can launch in `compose.yaml`.

## Troubleshooting

### Docker socket not found

The proxy expects the host Docker socket at `/var/run/docker.sock`.

If the Docker daemon uses another socket path, set `DOCKER_SOCK` when starting the project:

```console
DOCKER_SOCK=/path/to/docker.sock docker compose up -d --build
```

On VM-backed Docker environments such as Colima or Lima, bind mount source paths are resolved by the Docker daemon, not by the macOS host.

### Docker API version is rejected

The proxy reports the newest Docker API version it validates on `/_ping` and `/version`, so Docker CLI and Compose negotiate down to it without any configuration.
The proxy still refuses a request that names a newer version, which is what `DOCKER_API_VERSION` or a pinned version asks for.

### The Compose project cannot be loaded

The proxy and `app` must resolve the same Compose project.

This example mounts the project directory at the same absolute path in both containers and passes `PWD` to the proxy for Compose variable interpolation.

Run the example from `examples/quickstart`.
