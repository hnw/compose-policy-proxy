# Docker API policy

This document describes how `compose-policy-proxy` turns the security model into Docker API decisions.

The proxy compares Docker requests directly with the resolved Compose project. It does not first translate both sides into a large intermediate policy model. Canonicalization is applied only where Compose-aware clients and the Docker Engine use different representations for the same value.

The machine-checked field inventory in `internal/policy/inventory_test.go` is the source of truth for whether a Docker request field is compared, refused, or forwarded. This document explains the main rules in human-readable form.

## Comparison principles

Exact comparison is the default for security-sensitive fields.

Known safe-direction exceptions are used only where the ordering is simple and intentional. Capabilities are the main example: a request may add fewer capabilities and may drop more capabilities than Compose declares, but it may not restore a capability Compose dropped.

Fields outside the current security boundary are forwarded without comparison.

Known equivalent request encodings are accepted when they represent the same Compose operation. The policy does not require one particular Docker Compose version to serialize a value in one particular way.

## Compared security-sensitive fields

The following groups are checked against the resolved Compose service.

| Compose setting | Docker request | Policy concern |
| --- | --- | --- |
| `image` | `Config.Image` | program executed with the service's privileges |
| `entrypoint` | `Config.Entrypoint` | program selected by the Compose definition |
| `user` | `Config.User` | container privilege |
| `group_add` | `HostConfig.GroupAdd` | supplemental host groups |
| `privileged` | `HostConfig.Privileged` | isolation boundary |
| `cap_add`, `cap_drop` | `HostConfig.CapAdd`, `CapDrop` | Linux capability set |
| `security_opt` | `HostConfig.SecurityOpt` | seccomp, AppArmor, SELinux, no-new-privileges |
| `read_only` | `HostConfig.ReadonlyRootfs` | writable root filesystem |
| `runtime` | `HostConfig.Runtime` | host-side runtime selection |
| `sysctls` | `HostConfig.Sysctls` | kernel parameters |
| namespace settings | `PidMode`, `IpcMode`, `CgroupnsMode`, `UsernsMode`, `UTSMode` | host or foreign namespace access |
| mounts | `Mounts`, `Binds`, `Tmpfs` | host path, volume, or image access |
| devices | `Devices`, `DeviceCgroupRules`, `DeviceRequests` | host device access |
| `volumes_from` | `HostConfig.VolumesFrom` | another container's volumes |
| `cgroup_parent` | `HostConfig.CgroupParent` | host cgroup placement |
| `isolation` | `HostConfig.Isolation` | hypervisor/isolation mode |
| `network_mode` | `HostConfig.NetworkMode` | host or foreign network namespace |
| `networks` | endpoint names | Docker network attachment |
| `ports` | `HostConfig.PortBindings` | host listeners |

The command itself is not compared because command override is the purpose of `docker compose run SERVICE COMMAND`. The entrypoint remains constrained because replacing it changes the program chosen by the Compose service while preserving the rest of the service's capabilities.

## Capability comparison

Capabilities use a safe-direction subset rule rather than exact equality.

A request may:

- omit capabilities from Compose `cap_add`; and
- add extra entries to `cap_drop`.

A request may not:

- add a capability that Compose did not grant; or
- restore a capability that Compose explicitly dropped.

Capability names are canonicalized so equivalent spellings such as `NET_ADMIN`, `net_admin`, and `CAP_NET_ADMIN` compare identically.

## Security options

Compose `security_opt` entries are normalized to the representation sent to Docker before comparison. Seccomp profile files are read and compacted while the policy is built, because Compose sends the profile contents to the daemon rather than the filename. A profile that is missing or is not JSON prevents the proxy from starting, so a decision never depends on what the file holds at the moment the request arrives.

On container creation, undeclared security options are rejected because the proxy cannot generally determine whether an arbitrary additional option hardens or weakens the container.

On inspect, daemon-added security options may be present. The inspect path therefore permits additions that cannot be distinguished from daemon defaults while still requiring every Compose-declared option to remain effective.

## Mount policy

Docker represents Compose mounts through `HostConfig.Binds`, `HostConfig.Mounts` and `HostConfig.Tmpfs`. The policy reduces all supported representations to one internal mount comparison shape before deciding whether the request matches Compose.

The representation is not itself authoritative. The resulting mount semantics are.

The policy compares properties that affect which host or persistent state the container can reach or alter:

| Mount property | Why it is compared |
| --- | --- |
| type, source, target | selects the backing host path, volume, image, and container path |
| read-only | controls write access |
| bind propagation | can propagate mount changes across mount namespaces |
| recursive bind options | changes which parts of the source tree are visible or writable |
| `create_host_path` / `CreateMountpoint` | can make Docker create a host directory |
| SELinux relabel mode | changes labels on a host path |
| volume subpath | constrains the visible portion of a volume |
| `nocopy` | changes copying into persistent volume state |
| per-mount volume driver/options | invokes host-side driver behavior |
| volume labels | changes persistent volume metadata |
| image subpath | constrains the visible portion of an image mount |

Tmpfs size and mode, mount consistency, and similar resource/container-local options are forwarded.

Relative bind sources are resolved against the Compose project working directory. Named volume and network Compose keys are resolved to their Docker names. Resolution is one-way; Docker resource names are not mapped back to arbitrary Compose keys.

Secrets and file-backed configs that Compose materializes as bind mounts are added to the expected mount set before comparison.

## Port policy

`HostConfig.PortBindings` is checked asymmetrically because `docker compose run` does not publish service ports by default.

The request may omit bindings declared by the service. Every binding the request does contain must correspond to a Compose-declared binding.

`Config.ExposedPorts` is not itself sufficient to create a host listener and is therefore forwarded. `PublishAllPorts` is refused because it creates host listeners not described by the Compose project.

## Network policy

The requested network mode and the set of attached Docker network names are constrained by Compose.

A request may not:

- switch into host networking unless Compose declares it;
- join another container's network namespace unless Compose declares it;
- attach to an undeclared Docker network; or
- omit a network required by the service.

Endpoint metadata such as aliases, static addresses, MAC address, gateway priority, and endpoint driver options is forwarded once attachment to the network itself has been authorized.

Network creation is compared against the Compose network it claims to create: driver, driver options, internal, attachable, IPv4/IPv6 enablement, scope and management labels must all be declared. Ingress networks, config-only networks and external networks are refused, because Compose never creates them.

IPAM is compared pool by pool. Where the Compose network declares no IPAM, the request may not name an IPAM driver or driver options either: Compose sends no IPAM at all in that case, so such a value would be the client's choice of a host-side plugin the proxy cannot reason about. An empty driver and the Engine's built-in `default` are the same request, because the Engine substitutes the built-in IPAM driver for an empty name.

## Docker-only fields

Some Docker API fields do not have a usable Compose equivalent.

Security-sensitive examples are refused rather than guessed:

| Field | Treatment |
| --- | --- |
| `HostConfig.MaskedPaths`, `ReadonlyPaths` | refused on create when the request attempts to override daemon confinement |
| `HostConfig.Cgroup` | refused because it directly names a cgroup the proxy cannot resolve |
| `HostConfig.ContainerIDFile` | refused because its API contract names a host path for daemon output |
| `HostConfig.PublishAllPorts` | refused because it creates undeclared host listeners |
| `Config.Volumes` | refused because it declares an anonymous mount outside the canonical mount representations the policy compares |

Host-dependent values that Compose can express, such as `StorageOpt`, `VolumeDriver`, and runtime `Annotations`, are exact-matched instead of interpreted.

## Forwarded fields

Resource-consumption and container-local fields are not compared with Compose: limits and resource settings, lifecycle and logging options, environment, command, networking details such as DNS and endpoint metadata, and fields such as `Config.ExposedPorts` and container labels.

`internal/policy/inventory_test.go` lists every one of them with the reason it is forwarded.

## Existing containers

Existing-container operations require both Compose ownership labels and matching security-sensitive state.

The proxy reconstructs a create-like request from the Engine inspect result and reuses the same comparison logic in inspect mode.

Inspect mode skips only checks that cannot be reconstructed reliably because the daemon fills or normalizes the value after creation. Security-sensitive differences that remain observable continue to cause denial.

The request's Compose service label is a hint for create-time service matching, not an authority. Existing-container ownership requires the project label, a declared service, and a security-state match.

## Protected services

A service that mounts the upstream Docker socket directly is protected, for the reason [security-model.md](security-model.md) gives. The rule is applied as follows.

### On creation

A protected service is matched like any other and then refused by name: the refusal names the service and no field. Protected services are not filtered out of the candidate set, so the field comparisons still run for them and a mismatch is still reported as the field that differs.

The request's Compose service label only orders the candidates and cannot bypass the rule.

### On existing containers

Ownership is resolved first, from the Engine's inspect result. Only then is the operation checked against the protected set, using the service the inspect result resolved to.

| Operation | Effect | Protected service |
| --- | --- | --- |
| `GET /containers/json` | read-only | allowed |
| `GET /containers/{id}` | read-only | allowed |
| `GET /containers/{id}/json` | read-only | allowed |
| `POST /containers/{id}/wait` | read-only | allowed |
| `POST /containers/{id}/start` | control | denied |
| `POST /containers/{id}/stop` | control | denied |
| `POST /containers/{id}/kill` | control | denied |
| `DELETE /containers/{id}` | control | denied |
| `POST /containers/{id}/attach` | control | denied |
| `POST /containers/{id}/resize` | control | denied |

Each allowlisted container operation is either observation or control, and only observation is granted on a protected container. The observations are listed explicitly in `readOnlyOperations` in `internal/policy/routes.go`; every other allowlisted container operation is control, so a new endpoint is denied for a protected container without having to be classified.

Ordinary containers keep every operation the allowlist grants them.

## Docker API allowlist

Authorization is deny-by-default. The current allowlist is the set needed by `docker compose run` and `compose-exec`:

```text
/_ping                                       GET, HEAD
/version                                     GET
/info                                        GET

/containers/create                           POST
/containers/json                             GET
/containers/{id}                             GET, DELETE
/containers/{id}/json                        GET
/containers/{id}/attach                      POST
/containers/{id}/start                       POST
/containers/{id}/wait                        POST
/containers/{id}/stop                        POST
/containers/{id}/kill                        POST
/containers/{id}/resize                      POST

/images/create                               POST
/images/{name}/json                          GET

/networks                                    GET
/networks/{id}                               GET
/networks/create                             POST

/volumes                                     GET
/volumes/{name}                              GET
/volumes/create                              POST
```

An allowlisted endpoint with no rule of its own is refused rather than forwarded: joining the allowlist must not authorize an operation by itself.

## List scoping

A list request has to prove on its own that it cannot observe anything outside the project, because it is not addressed at a resource whose ownership could be checked.

- Containers must be filtered by the project label. Docker ANDs the patterns inside one filter key, so Compose's own `label` filter is narrow enough.
- Networks and volumes may instead be filtered by `name`, because that is how Compose looks a declared resource up.

A `name` filter is not an exact match: the Engine applies it as an unanchored regular expression, so the bare name Compose sends would also return `demo_frontend_other` and any other resource whose name contains it. The proxy therefore forwards the anchored, escaped name it authorized instead of the string the client sent. The forwarded pattern matches that one declared resource and nothing else, which is what makes the list scoped.

The filter keys of one request are ANDed by the Engine, so any other key can only narrow a result the scoping key already bounded. A request that carries neither a project label nor a declared name is refused.

## API version handling

Authorization removes the Docker API version prefix only to resolve the endpoint. The original versioned path is forwarded upstream so the Engine interprets the request using the client's negotiated API version.

Requests using an API version newer than the version validated by the current build are refused instead of being passed through unchecked.

The two negotiation endpoints answer for the proxy rather than for the Engine: `/_ping` reports the validated version in `API-Version`, and `/version` reports it in `ApiVersion`, which is the older of the Engine's version and the validated one.
Every other field of the Engine's answer is relayed unchanged, including a field a newer Engine adds.
A client therefore negotiates to a version the proxy forwards, while a request that names a newer version in its path is still refused.

The proxy reads the Engine's API versions once at startup, and refuses to start unless the two share at least one.
