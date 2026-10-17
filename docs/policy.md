# Docker API policy

This document describes the Docker API requests `compose-policy-proxy` permits and how they are checked against the resolved Compose project. See [security-model.md](security-model.md) for the threat model and limitations.

The policy is deny-by-default. An endpoint must be allowlisted, its method and API version must be supported, and its resource-specific authorization must succeed. Container, network, and volume create bodies are decoded strictly; unknown fields and trailing content are rejected.

The field inventory in `internal/policy/inventory_test.go` records whether each Docker request field is compared, refused, or forwarded. The rules below explain those decisions.

## Command selection

`--allow-command` selects which Compose commands the proxy authorizes. It defaults to every supported command, `run,up,down,start,stop,restart,pull,logs,exec`, and a value given on the command line replaces that default rather than adding to it.

A command names a set of Docker API permissions, not a CLI invocation. The proxy authorizes each request on its own and never authorizes a command as a whole.

| Command | Docker API operations it authorizes |
| --- | --- |
| `run` | one-off container create, and `start`, `stop`, `kill`, `remove`, `attach`, `restart`, and `resize` of that one-off container; the declared image pull, network create, and volume create that `run` needs |
| `up` | service container create, `start`, `stop`, `remove` and `rename` of a service container, and the network and volume creates it needs |
| `down` | `stop` and `remove` of a service container, and removal of a network of the project |
| `start` | `POST /containers/{id}/start` on a service container of the project |
| `stop` | `POST /containers/{id}/stop` on a service container of the project |
| `restart` | `POST /containers/{id}/restart` on a service container of the project |
| `pull` | `POST /images/create` for an image the project declares |
| `logs` | `GET /containers/{id}/logs` on a service container or one-off container of the project, and the `GET /events` stream that `docker compose logs --follow` opens |
| `exec` | exec create, start, and TTY resize on a container of the project; reading the exit status of that exec needs no command, as any other read-only operation does |

An unsupported name is refused at startup, a repeated name changes nothing, and an empty list authorizes no command at all.

`restart` requires its own permission; `start` and `stop` do not imply it. `up` and `down` do not imply each other: `down` cannot start a container, and `up` cannot remove a network.

The setting narrows what is authorized and nothing else. Every operation still has to pass the authorization conditions below: project and service ownership read from the Engine, the [configuration checks](#container-configuration), and the [protected service rule](#protected-services). Basic read-only operations remain available independently of `--allow-command`. Log access is an exception and requires `logs` permission.

`--allow-command` is not authentication. It does not decide which client is asking, so every client holding the socket gets the commands it names.

## Container authorization

### Creating containers

`POST /containers/create` requires these labels in `Config.Labels`:

| Label | Required value |
| --- | --- |
| `com.docker.compose.project` | the configured Compose project name |
| `com.docker.compose.service` | the name of a declared service |
| `com.docker.compose.oneoff` | `True` for the one-off container of `run`, `False` for the service container of `up` |

The one-off label decides which command is being performed: a create asking for a one-off container requires `run`, and one asking for the container of a service requires `up`. Any other value, including no label at all, is refused.

The proxy compares the request with the service named by the label. It does not search for another service whose settings happen to match. The request must pass the [configuration checks](#container-configuration) and must not target a protected service. The comparison is the same one the one-off create uses, so the security-sensitive settings a service container is created with are exactly the ones Compose declares.

Labels are client-supplied. They select the policy to apply; they do not prove that Docker Compose made the request. `docker compose run` and `docker compose up` supply these labels, but another Docker API client can also supply them.

### Existing containers

For an operation targeting an existing container, the proxy inspects it through the Engine and requires:

- a project label matching the configured project;
- a service label naming a declared service; and
- security-sensitive settings matching that service to the extent recoverable from inspect data.

The proxy does not trust labels supplied with the operation. It uses the labels and settings reported by the Engine. It keeps no container ownership database, so the same checks apply after a proxy restart.

Read-only operations are available for matching service containers, including normal service containers. Control operations require `com.docker.compose.oneoff=True` in the inspect result, except that a normal service container may be started, stopped, restarted and removed by the [commands](#command-selection) listed below, renamed by `up`, or [executed in](#exec). Control operations are denied for protected services. The [endpoint list](#docker-api-allowlist) identifies the operations in each group.

| Operation on a normal service container | Command |
| --- | --- |
| `POST /containers/{id}/start` | `start` or `up` |
| `POST /containers/{id}/stop` | `stop`, `up` or `down` |
| `DELETE /containers/{id}` | `down` or `up` |
| `POST /containers/{id}/rename` | `up` |
| `POST /containers/{id}/restart` | `restart` |
| `POST /containers/{id}/kill`, `/attach`, `/resize` | no command, since only a one-off container answers to them |

A removal may not ask for the options that act on something else: `v` would delete the volumes mounted on the container, which belongs to `down --volumes` and is not authorized, and `link` would rewrite the links other containers hold to it. `force` changes how a removal waits and is forwarded.

`POST /containers/{id}/rename` permits only the Compose-assigned name: `container_name` if specified, otherwise `<project>-<service>-<number>`. One-off containers cannot be renamed.

An attached `docker compose up`, which is `up` without `-d`, is not supported: it attaches to the service container, which no command authorizes for a normal service container. Use `up -d`.

Reading a container's logs is not among the read-only operations: it is decided by the `logs` command for both service containers and one-off containers, and a protected service's container is refused.

The one-off label restricts which containers a client may control, not how long they can run. A one-off container may run indefinitely or be started again.

A recreate performed by `up` is an ordinary removal followed by an ordinary create: the container is stopped and removed, and a new one is created from the same Compose definition and started. Nothing about it is authorized as a unit.

### Inspect-mode comparison

The Engine fills or normalizes some create-time values. The proxy compares existing containers in inspect mode, which omits comparisons that cannot reliably reconstruct the original request:

- an image-supplied entrypoint when Compose does not specify one; an explicit `entrypoint: []` remains checked;
- an image-supplied user when Compose declares no non-empty `user`;
- `Config.Volumes`, which can include image `VOLUME` declarations;
- runtime, namespace, masked-path, and read-only-path settings normalized by the Engine; and
- additional security options supplied by the Engine, while still requiring Compose-declared options.

For a fixed `network_mode`, inspect may report an Engine-created endpoint with the mode's own name (for example, `none` or `host`). That endpoint is ignored; the network mode and any additional endpoints remain checked.

Inspect authorization does not prove that every field of the original create request would still pass today's policy. Recreate containers after changing security-sensitive Compose settings.

### Protected services

A service whose resolved mounts give it direct access to the upstream Docker socket is protected, as defined in [security-model.md](security-model.md). Its containers cannot be created or controlled through the proxy, even when their configuration matches Compose. Read-only operations remain available.

The service is identified before this restriction is applied. Naming a different service in a create request does not bypass it, because the request must match the named service's configuration.

## Exec

`docker compose exec` can execute arbitrary commands, with custom environment and working directory, in an existing project container without increasing its privileges.

### Creating an exec

`POST /containers/{id}/exec` requires an owned, non-protected container whose inspected configuration matches Compose. Both regular service containers and one-off containers are allowed. The exec request has these additional constraints:

| Field | Rule |
| --- | --- |
| `Privileged` | refuse `true`; an exec adds no privilege of its own to the container's |
| `User` | refuse any non-empty value, so that the exec runs as the container's own user |
| `Cmd`, `Env`, `WorkingDir`, `Tty`, `AttachStdin`, `AttachStdout`, `AttachStderr`, `DetachKeys`, `ConsoleSize` | forwarded |

Unknown fields in the exec creation request are rejected.

### Operating on an exec

For `/exec/{id}/start`, `/exec/{id}/resize`, and `/exec/{id}/json`, the proxy uses Engine exec inspect to identify the containing container and applies [existing-container rules](#existing-containers). No exec ownership state is stored in the proxy, including for exec instances created outside it.

Starting or resizing additionally requires:

- `exec` permission;
- a process configuration in the Engine's answer, since an answer without one, or without the privilege in it, cannot be judged on;
- `Privileged` reported as false;
- a reported user exactly matching the container's configured user;
- for a start, a `Tty` that matches the terminal the exec was created with.

Reading an exec is a read-only operation: it requires ownership but no command, and is refused for a protected service's container.

## Container configuration

Security-sensitive settings are compared with the resolved service. Exact matching is the default, with the exceptions described below.

| Compose setting | Docker request field | Restriction |
| --- | --- | --- |
| `image` | `Config.Image` | declared image |
| `entrypoint` | `Config.Entrypoint` | declared entrypoint |
| `user`, `group_add` | `Config.User`, `HostConfig.GroupAdd` | container user and supplemental groups |
| `privileged`, `read_only` | `HostConfig.Privileged`, `ReadonlyRootfs` | privileges and root filesystem access |
| `cap_add`, `cap_drop` | `HostConfig.CapAdd`, `CapDrop` | capability limits |
| `security_opt` | `HostConfig.SecurityOpt` | seccomp and other security options |
| `runtime`, namespace settings | `HostConfig.Runtime`, `PidMode`, `IpcMode`, `CgroupnsMode`, `UsernsMode`, `UTSMode` | runtime and namespace isolation |
| `sysctls`, `cgroup_parent`, `isolation` | corresponding `HostConfig` fields | kernel and host-dependent isolation settings |
| mounts and `volumes_from` | `HostConfig.Mounts`, `Binds`, `Tmpfs`, `VolumesFrom` | mounted data and host paths |
| devices | `Devices`, `DeviceCgroupRules`, `DeviceRequests` | host device access |
| `network_mode`, `networks` | `HostConfig.NetworkMode`, `Config.NetworkDisabled`, endpoint names | Docker network reachability |
| `ports` | `HostConfig.PortBindings` | published host ports |

`Config.Cmd` and environment variables are not compared: callers may choose the command and environment within the service's authorized execution environment. Other resource-consumption, logging, lifecycle, and container-local settings are generally forwarded, including restart policy, working directory, DNS configuration, and endpoint metadata. The field inventory records the exact treatment of each field.

### Capabilities and security options

Capabilities are compared in the safe direction: a request may omit some `cap_add` entries or drop additional capabilities, but it may not add undeclared capabilities or restore any that Compose drops. Capability names are normalized before comparison.

Compose `security_opt` values are converted to Docker's representation. Seccomp profile files are loaded and resolved at proxy startup because Docker receives their contents, not their filenames. A missing or invalid profile prevents startup. Undeclared security options are refused on create; inspect mode allows daemon-added options but still requires the declared ones.

### Mounts

`HostConfig.Binds`, `HostConfig.Mounts`, and `HostConfig.Tmpfs` are compared by their resolved mount semantics rather than by their API representation. The request must contain every Compose-declared mount and no additional mount or duplicate target.

The comparison covers mount type, source, target, read-only status, bind propagation and recursive options, host-path creation, SELinux relabeling, volume and image subpaths, volume `nocopy`, and driver or label options that affect host or persistent state. Resource and container-local options such as tmpfs size and mode are forwarded.

Relative bind sources are resolved against the Compose project directory. Named volumes are resolved to Docker resource names. File-backed Compose secrets and configs are included as their resulting bind mounts.

### Networking and ports

The network mode and attached network names must match the Compose service. Undeclared attachments and missing required networks are refused. Endpoint metadata such as aliases, addresses, gateway priority, and driver options is forwarded after the network attachment is authorized.

`docker compose run` omits published service ports by default, so a request may omit Compose-declared `PortBindings`. Any binding it does request must match a declared binding. `Config.ExposedPorts` is forwarded because it does not create a host listener; `HostConfig.PublishAllPorts` is refused.

### Fields not represented safely by Compose

Some Docker-only values are refused instead of compared:

| Docker field | Rule |
| --- | --- |
| `HostConfig.MaskedPaths`, `ReadonlyPaths` | refuse create-time overrides of daemon confinement |
| `HostConfig.Cgroup` | refuse direct cgroup selection |
| `HostConfig.ContainerIDFile` | refuse a daemon write to an arbitrary host path |
| `HostConfig.PublishAllPorts` | refuse undeclared host listeners |
| `Config.Volumes` | refuse on create; skip on inspect because images may declare volumes |

Host-dependent fields that Compose can express, including `StorageOpt`, `VolumeDriver`, and runtime `Annotations`, are compared exactly rather than assumed safe.

## Images, networks, and volumes

Image inspection and pulling are limited to references declared by the Compose project. Image names are normalized for implicit registry, namespace, and tag defaults, so a reference containing slashes is compared as a whole. Pull requests cannot use `fromSrc`, bulk or multi-image pulls, or undeclared references.

`POST /images/create` is authorized by `pull` or by `run`, because a pull is both what `docker compose pull` performs and what `run` needs before it can create anything. `up` pulls the same images but gains no permission of its own for it, so an `up` that has to fetch an image still requires `pull` or `run`. The image a protected service uses can be pulled like any other declared image: fetching an image is not an operation on that service's container.

Network and volume inspection is limited to names declared in the project, including external resources. A network may also be addressed by the identifier the Engine assigned it, which is how Compose reaches one after listing them; the proxy resolves that identifier by reading the network and then requires the same declared name.

Creating a resource requires its resolved name and a matching Compose definition; resources marked `external` cannot be created through the proxy.

- **Networks:** driver, driver options, `internal`, `attachable`, IPv4/IPv6 settings, management labels, and IPAM must match. Ingress and config-only networks are refused. Network scope may be empty, `local`, or `swarm`. IPAM pools are compared individually; if Compose declares no IPAM, a request cannot introduce an IPAM plugin or options (the built-in `default` driver is allowed).
- **Volumes:** driver, driver options, and required Compose management labels must match. Cluster volume specifications are refused.

Removing a network is what `down` performs, and requires `down` and all of the following:

- the network is one the Compose definition declares, including the implicit `default` network;
- the declaration is not `external: true`, since such a network belongs to whoever created it; and
- the Engine reports `com.docker.compose.project=<project>` and `com.docker.compose.network=<key>` on it, the pair Compose itself matches. A matching name alone proves nothing, and neither does one label of the pair: a network an earlier Compose file created under a different key keeps the name but no longer carries the key.

Whether an endpoint is still attached is left to the Engine, which refuses the removal itself. A volume is never removed: `down --volumes` is out of scope, and the volume removal API is not allowlisted.

## List requests

Lists have no individual resource to inspect, so requests must be scoped before forwarding:

- Container lists require a filter for `com.docker.compose.project=<project>`.
- Network and volume lists require that project filter or a `name` filter naming a declared resource.

Docker treats a `name` filter as an unanchored regular expression. The proxy replaces an authorized name filter with an escaped, anchored expression so similarly named resources cannot be included. Other filters are preserved because Docker combines different filter keys with AND.

## Event streams

`docker compose logs --follow` also opens an event watch, so that it can follow containers created while it is running. `GET /events` is authorized by `logs` and observes the project's own containers only:

- the `filters` must name `com.docker.compose.project=<project>` and `container`, each as the only value of its key. The engine ORs the values of the `type` key, so a second value there would observe more event types, and ANDs the values of the `label` key, so a second value there describes no container the project has;
- any other key the client sent is dropped, so only those two conditions reach the Engine;
- a request without filters, naming another project, or naming another event type is refused.

An event carries the labels, image, and exit code of the containers it names, which the inspect operation already exposes for the project's containers. Events of a protected service's container are within this scope: observing them is not acting on the container.

## Docker API allowlist

Only the following methods and endpoints are supported. Unknown endpoints, unsupported methods, and endpoints without a corresponding authorization rule are denied.

```text
/_ping                                       GET, HEAD
/version                                     GET
/info                                        GET

/containers/create                           POST         one-off create (`run`), or service create (`up`)
/containers/json                             GET          project-scoped list
/containers/{id}                             GET          read-only
/containers/{id}                             DELETE       one-off control, or `down`/`up` of a service container
/containers/{id}/json                        GET          read-only
/containers/{id}/wait                        POST         read-only
/containers/{id}/attach                      POST         one-off control
/containers/{id}/exec                        POST         `exec` of an owned container
/containers/{id}/rename                      POST         `up` gives the container its compose name
/containers/{id}/start                       POST         one-off control, or `start`/`up` of a service container
/containers/{id}/stop                        POST         one-off control, or `stop`/`up`/`down` of a service container
/containers/{id}/restart                     POST         one-off control, or `restart` of a service container
/containers/{id}/kill                        POST         one-off control
/containers/{id}/resize                      POST         one-off control
/containers/{id}/logs                        GET          `logs` of any owned container

/exec/{id}/json                              GET          read-only
/exec/{id}/start                             POST         `exec`, bidirectional stream unless detached
/exec/{id}/resize                            POST         `exec`

/images/create                               POST         declared image pull, by `pull` or `run`
/images/{name}/json                          GET          declared image inspect

/events                                      GET          project container events, by `logs`

/networks                                    GET          scoped list
/networks/{id}                               GET          declared network inspect, by name or by engine id
/networks/{id}                               DELETE       `down` of a network this project owns
/networks/create                             POST         declared network create

/volumes                                     GET          scoped list
/volumes/{name}                              GET          declared volume inspect
/volumes/create                              POST         declared volume create
```

A control operation also requires a matching existing container, an allowed [command](#command-selection), and a service that is not protected. Read-only operations on individual containers require the same ownership and inspect-mode comparison but do not require the one-off label.

A followed log stream and the event watch beside it keep their response bodies open after the headers. They are ordinary HTTP responses rather than a hijacked connection, and their bodies are relayed chunk by chunk so that a client following them receives output as the daemon writes it. An attached exec start uses a bidirectional stream like container attach; a detached start uses an ordinary HTTP response.

The proxy authorizes Docker API requests one at a time. A Compose command that needs an API outside this list fails partway through, leaving whatever it had already done in place, and the proxy neither rolls that back nor excludes resources from the operation to make it succeed.

This version does not cover `down --volumes`, `down --rmi`, `up --remove-orphans` or `up --build`. The options are not parsed and refused by name; the operations fail because the Docker API they need is not authorized. An image a service needs may still be pulled by `up`, through the existing `pull` permission. Other Docker Compose workflows, including `build` and `push`, are not supported through this socket.

The proxy process itself, and the Compose project it serves, are managed from the host rather than through this socket.

## Docker API versions

The proxy recognizes Docker API versions only through the newest version it has validated. Requests naming a newer version are denied, even when the Engine itself supports them. The original versioned request path is forwarded after authorization.

During API negotiation, `/_ping` and `/version` report the lower of the Engine's version and the proxy's validated version, while preserving the other Engine response fields. At startup, the proxy verifies that it and the Engine support at least one common API version.
