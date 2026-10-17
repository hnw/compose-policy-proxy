# compose-policy-proxy

Some applications running in containers need to launch other containers, such as bots or CI runners executing command-line tools. Docker-outside-of-Docker (DooD) makes this possible by giving the application access to the host Docker socket. However, this also grants broad control over the Docker Engine.

`compose-policy-proxy` provides a restricted Docker socket instead. It uses an existing `compose.yaml` as its policy, allowing applications to run declared services without unrestricted Docker access—even if the application container is compromised.

## How it works

```text
Application container
        |
        | Restricted Docker socket
        v
compose-policy-proxy
        |
        | Host Docker socket
        v
    Docker Engine
        |
        v
  Sibling container
```

The application connects through `DOCKER_HOST`. The proxy checks each Docker API request against the resolved Compose project before forwarding it to the Engine.

For example:

```yaml
services:
  pandoc:
    image: pandoc/core:3.11.0.0
    volumes:
      - ./documents:/data
    working_dir: /data
```

The application can run the `pandoc` service with different commands and arguments, but cannot use another image, add undeclared mounts, or enable privileged mode. The proxy enforces the service's security-sensitive configuration, not the behavior of the command it runs.

## Quick start

Try the [working example](examples/quickstart):

```console
git clone https://github.com/hnw/compose-policy-proxy.git
cd compose-policy-proxy/examples/quickstart

docker compose up -d
docker compose exec app sh
```

You are now inside the `app` container, which has Docker Compose but only a restricted Docker socket. Run a tool as a sibling container:

```console
docker compose run --rm tool echo "hello through the proxy"
```

The proxy allows the `tool` service because it is defined in `compose.yaml`, while denying Docker operations outside the permitted configuration.

Exit the application container, then view authorization decisions and clean up from the host:

```console
exit
docker compose logs policy-proxy
docker compose down
```

The `app` container represents a CI runner or bot that launches predefined tools without unrestricted access to the Docker Engine.

See the [example README](examples/quickstart/README.md) for denied-request examples and troubleshooting.

## Supported operations

The proxy supports the Compose commands `run`, `up`, `down`, `start`, `stop`, `restart`, `pull`, `logs`, and `exec`.

`run` creates one-off containers. `up` creates and starts the containers of the project, and recreates them when they no longer match the Compose file; use `up -d`, since an attached `up` is not supported. `down` stops and removes them, along with the networks the project owns. `start`, `stop`, and `restart` operate on service containers that already exist. `exec` runs commands in existing project containers. `pull` fetches declared images, and `logs` reads project container logs.

`--allow-command` selects which of these commands are available. It defaults to all of them, and naming it replaces that default:

```console
# Every supported command (default)
compose-policy-proxy

# Allow only one-off containers
compose-policy-proxy --allow-command=run

# Starting and stopping existing services, without creating one-off containers
compose-policy-proxy --allow-command=start,stop

# Bringing the project up and taking it down again
compose-policy-proxy --allow-command=up,down
```

`logs` requires its own permission because container output may contain secrets. The detailed permission rules are in [Docker API policy](docs/policy.md).

Other Compose workflows, including `build` and `push`, are not supported through the restricted socket, and neither are `down --volumes`, `down --rmi`, `up --remove-orphans` or `up --build`.

The proxy itself, and the Compose project it serves, must be managed directly from the host.

## Security model

Clients with access to the restricted socket are untrusted. The proxy rejects operations outside the resolved Compose policy, but does not make an unsafe Compose definition safe. It does not restrict commands run inside permitted containers, general outbound network access, or resource consumption. Anyone who can access the restricted socket receives the same configured permissions.

See [Security model](docs/security-model.md) for the threat model and limitations, and [Docker API policy](docs/policy.md) for the detailed enforcement rules.

## Configuration

The proxy is available as a distroless container image for `linux/amd64` and `linux/arm64`:

`ghcr.io/hnw/compose-policy-proxy:latest`

It requires:

- Access to the host Docker socket
- Read access to the Compose project configuration
- A shared directory for its restricted Unix socket

The application and proxy must resolve the same Compose project. Bind mount paths must also be accessible to the Docker Engine.

The Compose project is loaded at startup and treated as fixed. After changing the Compose file, stop and remove the whole project, proxy included, from the host and start it again; a running proxy keeps authorizing the project it loaded, not the one on disk.

| Flag | Default | Description |
| --- | --- | --- |
| `--listen` | `/run/compose-policy-proxy/docker.sock` | Restricted socket path |
| `--docker-host` | `/var/run/docker.sock` | Host Docker socket |
| `--socket-mode` | `0660` | Restricted socket permissions |
| `--allow-command` | `run,up,down,start,stop,restart,pull,logs,exec` | Compose commands to allow |
| `--log-format` | `text` | `text` or `json` |
| `--log-level` | `info` | Logging verbosity |

See [examples/quickstart](examples/quickstart) for a complete deployment.

## Documentation

- [Security model](docs/security-model.md) — Threat model and limitations
- [Docker API policy](docs/policy.md) — Authorization rules and supported endpoints
- [Development](docs/development.md) — Building, testing, and releases

## License

[MIT](LICENSE)
