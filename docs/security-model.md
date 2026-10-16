# Security model

`compose-policy-proxy` treats the resolved Compose project as a capability boundary for Docker API access.

The proxy assumes that a client with access to its Unix socket may be hostile. The client is allowed to exercise what the Compose project already grants, but it must not use the Docker API to acquire additional host access, privilege, isolation escape, or Docker control-plane authority.

The proxy does not judge whether the Compose project itself is safe. A dangerous capability explicitly granted by Compose remains granted through the proxy.

The proxy restricts the container execution environment, not the command being run. A client may override the command and arguments and change container environment variables within an authorized service. Any access available to that service remains available to the commands it runs.

## Protected boundaries

The current policy protects five boundaries.

| Boundary | Examples of what is prevented |
| --- | --- |
| Host confidentiality | reading undeclared host paths, another container's volumes, host devices, credentials, or the Docker socket |
| Host integrity | writing undeclared host paths, writing through extra mounts, accessing devices, or mutating Docker resources outside the project |
| Isolation | enabling `privileged`, adding undeclared capabilities, weakening security options, joining host or foreign namespaces, changing runtime, or restoring writable access Compose removed |
| Docker control plane | operating on containers, networks, or volumes outside the Compose project |
| The proxy's own authority | creating, starting, stopping, killing, removing, or attaching to a service that holds the Docker socket directly |

Docker-specific network exposure is also restricted when the Docker API is the point where that exposure is created. Examples include host networking, joining another container's network namespace, attaching to an undeclared Docker network, publishing all ports, or binding a host port that Compose did not declare.

## Out of scope

Two concerns are intentionally outside the current policy boundary.

**General outbound network abuse.** A container may use the network it has already been given to contact the LAN or Internet. Restricting those destinations belongs to a network policy, firewall, or egress proxy rather than to this Docker API proxy. The proxy still restricts Docker-specific changes that create new exposure, such as `NetworkMode: host`, undeclared network attachments, and undeclared host port bindings.

**Resource exhaustion.** CPU, memory, shared memory, PID limits, file-descriptor limits, restart policy, logging configuration, and similar availability controls are not constrained against the Compose value. The proxy forwards those fields, and does not attempt to define a general "safer than Compose" ordering for them.

## Field classification

Every Docker request field inspected by the policy belongs to one of five classes.

| Class | Meaning | Policy action |
| --- | --- | --- |
| A | can widen host confidentiality, host integrity, or isolation | compare with Compose or refuse |
| B | can add Docker-specific network exposure | compare with Compose |
| C | affects availability or resource consumption | forward |
| D | affects container-local behavior, lifecycle, or general network behavior | forward |
| E | security impact cannot be bounded cheaply | refuse, or exact-match when Compose can express the value |

The classification is intentionally based on security effect rather than on whether Compose happens to have a corresponding field.

Fields whose effect depends on host-installed storage drivers, runtimes, or plugins are not assumed to be harmless. When Compose can express them, the proxy uses exact matching instead of trying to infer which value is safer.

The detailed field classification and comparison rules are documented in [policy.md](policy.md).

## Fail-closed behavior

Unknown Docker API fields are not silently accepted.

Request bodies are decoded strictly. A field that the Moby types do not know fails decoding. In addition, the test suite classifies every field of the Docker request structures the policy reads, so a Moby dependency upgrade that adds a known-but-unclassified field fails tests until that field receives an explicit policy decision.

Authorization is deny-by-default in both directions. An operation no rule covers is refused, and a request that cannot prove it stays inside the project -- a list operation, say -- is refused rather than read as unrestricted access.

## One-off containers

`docker compose run` creates one-off containers. The proxy allows these containers to be created and controlled, but ordinary service containers cannot be created or controlled through the restricted socket. Read-only operations remain available for existing service containers that pass the ownership and configuration checks.

One-off containers are identified by `com.docker.compose.oneoff=True`. Because this label is client-controlled, it does not prove that a request came from Docker Compose. One-off containers must still match their Compose service configuration and cannot belong to a protected service. The label does not limit how long a container can run.

## Existing-container ownership

Operations on an existing container require both project identity and matching security-sensitive state.

A Compose project label alone is not ownership: a foreign container could copy the label. Matching security state alone is also insufficient: another project could legitimately create an identical container.

The proxy therefore requires both:

- the container belongs to the configured Compose project and names a declared service; and
- the security settings that an inspect result can still show match what that service grants.

Ownership is derived from the Engine's current inspect result rather than from proxy-local memory, so restarting the proxy does not erase ownership information. A client-supplied label cannot influence which service a container is judged against.

The second condition is a check of the container's state now, not a replay of the request that created it. The daemon completes and normalizes the values it was given, so an inspect result cannot say which of them the client asked for. Inspect mode therefore skips the comparisons whose original value is not recoverable, and nothing more: it does not relax the create-time policy. Authorizing an existing container does not prove that every setting of its create request still matches the current Compose definition.

Existing containers are checked against the current Compose definition, but some create-time settings cannot be reliably reconstructed from inspect results. Recreate existing containers after changing security-sensitive settings.

## Protected services

A Compose project often contains the proxy itself. Such a service is mounted with the host Docker socket, so anything able to create or control it holds Docker directly and answers to nothing.

Those services are **protected**. Field comparison cannot express this restriction, because every field of a request that launches a protected service is exactly what Compose declares. The rule is therefore separate, and narrower: it recognizes the service, and then refuses the operation.

A service is protected when **any** of its resolved Compose mounts satisfies all three conditions:

```text
Type == bind
AND Destination == dockerHost
AND Source != restrictedSocket
```

- `dockerHost` is the upstream Docker socket, from `--docker-host` (default `/var/run/docker.sock`).
- `restrictedSocket` is the proxy's own listening socket, from `--listen` (default `/run/compose-policy-proxy/docker.sock`).
- `Source` and `Destination` are the host source and container target of the resolved Compose mount.

Resolved mounts include the read-only binds Compose derives from `secrets:` and `configs:`, because that is the mount the container ends up with. Delivering the socket either way does not make a service unprotected.

The destination is what is compared rather than an assumed host location, because a deployment may serve the Engine socket somewhere else, such as a rootless Docker socket. The source exclusion covers the deployment where the proxy runs on the host and hands its restricted socket to application containers at the usual Docker socket path: that container reaches the Engine only through the proxy.

The restriction applies through every Docker API endpoint that can reach the container, not only those under `/containers/`. Ownership is resolved first, so the check can only narrow a decision already made from the container itself rather than from a client-supplied label. [policy.md](policy.md) lists which operations remain available on a protected container.

### Limitations

Detection reads the Compose file, not the host. It cannot answer:

- a parent directory mounted at a path that contains the socket;
- access through a symlink;
- a Docker socket mounted at some other container path;
- Docker API access over TCP or SSH;
- a custom volume driver exposing host paths;
- any other way of reaching an Engine that is not a bind mount of the socket.

The rule also does not verify what a host path actually is. A bind of an unrelated file onto the Docker socket path is treated as protected, because the destination is the path a client can reach Docker through.

Changing which services are protected requires restarting the proxy, like every other policy decision.

## Policy authority lifetime

The proxy resolves the Compose project once at startup. That resolved project is the policy authority for the lifetime of the process, including the set of protected services derived from it and the seccomp profiles its services name.

Changing a Compose file does not alter the policy of an already-running proxy. A policy update therefore consists of changing the Compose definition and restarting the proxy.
