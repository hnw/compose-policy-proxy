# Docker API policy

This document describes the Docker API requests `compose-policy-proxy` permits and how they are checked against the resolved Compose project. See [security-model.md](security-model.md) for the threat model and limitations.

The policy is deny-by-default. An endpoint must be allowlisted, its method and API version must be supported, and its resource-specific authorization must succeed. Container, network, and volume create bodies are decoded strictly; unknown fields and trailing content are rejected.

The field inventory in `internal/policy/inventory_test.go` records whether each Docker request field is compared, refused, or forwarded. The rules below explain those decisions.

## Command selection

`--allow-command` selects which Compose commands the proxy authorizes. It defaults to every supported command, `run,start,stop`, and a value given on the command line replaces that default rather than adding to it.

| Command | Docker API operations it authorizes |
| --- | --- |
| `run` | one-off container create, and `start`, `stop`, `kill`, `remove`, `attach`, and `resize` of that one-off container; the declared image pull, network create, and volume create that `run` needs |
| `start` | `POST /containers/{id}/start` on a service container of the project |
| `stop` | `POST /containers/{id}/stop` on a service container of the project |

An unsupported name is refused at startup, a repeated name changes nothing, and an empty list authorizes no command at all.

The setting narrows what is authorized and nothing else. Every operation still has to pass the authorization conditions below: project and service ownership read from the Engine, the [configuration checks](#container-configuration), and the [protected service rule](#protected-services). Read-only operations are available under the existing conditions whatever the setting says, since `--allow-command` names no endpoint that observes without acting.

`--allow-command` is not authentication. It does not decide which client is asking, so every client holding the socket gets the commands it names.

## Container authorization

### Creating containers

`POST /containers/create` requires these labels in `Config.Labels`:

| Label | Required value |
| --- | --- |
| `com.docker.compose.project` | the configured Compose project name |
| `com.docker.compose.service` | the name of a declared service |
| `com.docker.compose.oneoff` | `True` |

The proxy compares the request with the service named by the label. It does not search for another service whose settings happen to match. The request must pass the [configuration checks](#container-configuration) and must not target a protected service.

Labels are client-supplied. They select the policy to apply; they do not prove that Docker Compose made the request. `docker compose run` supplies these labels, but another Docker API client can also supply them.

Normal service containers cannot be created through the restricted socket. A `docker compose run` invocation that needs a dependency therefore needs that container prepared outside the proxy, which may then start it through [the `start` command](#command-selection).

### Existing containers

For an operation targeting an existing container, the proxy inspects it through the Engine and requires:

- a project label matching the configured project;
- a service label naming a declared service; and
- security-sensitive settings matching that service to the extent recoverable from inspect data.

The proxy does not trust labels supplied with the operation. It uses the labels and settings reported by the Engine. It keeps no container ownership database, so the same checks apply after a proxy restart.

Read-only operations are available for matching service containers, including normal service containers. Control operations require `com.docker.compose.oneoff=True` in the inspect result, except that a normal service container may be started and stopped by the [commands](#command-selection) of the same name. Control operations are denied for protected services. The [endpoint list](#docker-api-allowlist) identifies the operations in each group.

The one-off label restricts which containers a client may control, not how long they can run. A one-off container may run indefinitely or be started again.

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

Image inspection and pulling are limited to references declared by the Compose project. Image names are normalized for implicit registry, namespace, and tag defaults. Pull requests cannot use `fromSrc`, bulk or multi-image pulls, or undeclared references.

Network and volume inspection is limited to names declared in the project, including external resources. Creating a resource requires its resolved name and a matching Compose definition; resources marked `external` cannot be created through the proxy.

- **Networks:** driver, driver options, `internal`, `attachable`, IPv4/IPv6 settings, management labels, and IPAM must match. Ingress and config-only networks are refused. Network scope may be empty, `local`, or `swarm`. IPAM pools are compared individually; if Compose declares no IPAM, a request cannot introduce an IPAM plugin or options (the built-in `default` driver is allowed).
- **Volumes:** driver, driver options, and required Compose management labels must match. Cluster volume specifications are refused.

## List requests

Lists have no individual resource to inspect, so requests must be scoped before forwarding:

- Container lists require a filter for `com.docker.compose.project=<project>`.
- Network and volume lists require that project filter or a `name` filter naming a declared resource.

Docker treats a `name` filter as an unanchored regular expression. The proxy replaces an authorized name filter with an escaped, anchored expression so similarly named resources cannot be included. Other filters are preserved because Docker combines different filter keys with AND.

## Docker API allowlist

Only the following methods and endpoints are supported. Unknown endpoints, unsupported methods, and endpoints without a corresponding authorization rule are denied.

```text
/_ping                                       GET, HEAD
/version                                     GET
/info                                        GET

/containers/create                           POST         one-off create
/containers/json                             GET          project-scoped list
/containers/{id}                             GET          read-only
/containers/{id}                             DELETE       one-off control
/containers/{id}/json                        GET          read-only
/containers/{id}/wait                        POST         read-only
/containers/{id}/attach                      POST         one-off control
/containers/{id}/start                       POST         one-off control, or `start` of a service container
/containers/{id}/stop                        POST         one-off control, or `stop` of a service container
/containers/{id}/kill                        POST         one-off control
/containers/{id}/resize                      POST         one-off control

/images/create                               POST         declared image pull
/images/{name}/json                          GET          declared image inspect

/networks                                    GET          scoped list
/networks/{id}                               GET          declared network inspect
/networks/create                             POST         declared network create

/volumes                                     GET          scoped list
/volumes/{name}                              GET          declared volume inspect
/volumes/create                              POST         declared volume create
```

A control operation also requires a matching existing container, an allowed [command](#command-selection), and a service that is not protected. Read-only operations on individual containers require the same ownership and inspect-mode comparison but do not require the one-off label.

Other Docker Compose workflows, including `up`, `down`, `exec`, `logs`, `build`, and `push`, are not supported through this socket.

## Docker API versions

The proxy recognizes Docker API versions only through the newest version it has validated. Requests naming a newer version are denied, even when the Engine itself supports them. The original versioned request path is forwarded after authorization.

During API negotiation, `/_ping` and `/version` report the lower of the Engine's version and the proxy's validated version, while preserving the other Engine response fields. At startup, the proxy verifies that it and the Engine support at least one common API version.
