# compose-policy-proxy

A Docker API proxy that restricts container operations to those permitted by a Docker Compose project.

Docker-outside-of-Docker (DooD) lets a container launch sibling containers, but mounting the host Docker socket gives it broad control over the Docker Engine.

**compose-policy-proxy** provides a restricted Docker socket instead. It uses an existing `compose.yaml` as the policy, allowing applications to launch containers without granting unrestricted Docker access.

It is designed for bots, automation services, and other applications that execute predefined containerized tools.

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

The application can run the `pandoc` service with different commands and arguments. It cannot use another image, mount additional host directories, or enable privileged mode unless the Compose configuration permits it.

**The Compose project defines what is allowed.** The proxy restricts the container's execution environment, not the commands it runs.

## Quick start

Try the [working example](examples/quickstart):

```console
git clone https://github.com/hnw/compose-policy-proxy.git
cd compose-policy-proxy/examples/quickstart

docker compose up -d --build
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

The proxy currently supports the Docker API operations needed for:

- `docker compose run`
- [compose-exec](https://github.com/hnw/compose-exec)

Other Compose workflows, including `up`, `down`, `exec`, `logs`, `build`, and `push`, are not supported through the restricted socket.

The proxy itself must be managed directly from the host.

## Security model

The proxy treats a client with access to its socket as untrusted, and enforces the security-sensitive settings the Compose project declares. Operations it does not support are denied by default, and a service that mounts the host Docker socket itself cannot be created or controlled through the proxy.

It does not restrict the commands a container runs, general outbound network traffic, or resource consumption, and it does not judge whether the Compose configuration itself is safe.

See [Security model](docs/security-model.md) for the threat model and limitations, and [Docker API policy](docs/policy.md) for the detailed enforcement rules.

## Configuration

The proxy is available as a distroless container image for `linux/amd64` and `linux/arm64`:

`ghcr.io/hnw/compose-policy-proxy:latest`

It requires:

- Access to the host Docker socket
- Read access to the Compose project configuration
- A shared directory for its restricted Unix socket

The application and proxy must resolve the same Compose project. Bind mount paths must also be accessible to the Docker Engine.

The Compose project is loaded at startup. Restart the proxy after changing its configuration.

| Flag | Default | Description |
| --- | --- | --- |
| `--listen` | `/run/compose-policy-proxy/docker.sock` | Restricted socket path |
| `--docker-host` | `/var/run/docker.sock` | Host Docker socket |
| `--socket-mode` | `0660` | Restricted socket permissions |
| `--log-format` | `text` | `text` or `json` |
| `--log-level` | `info` | Logging verbosity |

Use `--help` for CLI options. On `/_ping` and `/version` the proxy reports the newest Docker API version it validates, so Docker CLI and Compose negotiate down to it without any environment variable.
A request that names a newer version in its path is still refused.

See [examples/quickstart](examples/quickstart) for a complete deployment.

## Documentation

- [Security model](docs/security-model.md) — Threat model and limitations
- [Docker API policy](docs/policy.md) — Authorization rules and supported endpoints
- [Development](docs/development.md) — Building, testing, and releases

## License

[MIT](LICENSE)
