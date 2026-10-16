# Security model

`compose-policy-proxy` uses the resolved Compose project as the authority for Docker API access through its restricted socket.

## Threat model

Any client with access to the socket is treated as untrusted, and the proxy assumes that such a client may be compromised. It may issue arbitrary Docker API requests, read the Compose configuration, and discover the proxy's implementation. The proxy prevents it from acquiring host access, privileges, isolation settings, or Docker control-plane authority beyond what the Compose project permits.

The Compose configuration, the proxy process, and the upstream Docker socket must remain outside the attacker's control. The proxy does not protect against an attacker who can modify its policy or access the upstream Docker Engine directly.

The Compose project itself is trusted. If it grants a dangerous capability, the proxy does not revoke it. Within an authorized execution environment, clients may override commands, arguments, and environment variables.

Security does not depend on keeping the proxy's implementation or authorization rules secret.

## Security boundaries

The policy protects five boundaries.

| Boundary | Examples of what is prevented |
| --- | --- |
| Host confidentiality | reading undeclared host paths, another container's volumes, host devices, credentials, or the Docker socket |
| Host integrity | writing undeclared host paths, accessing extra mounts or devices, or modifying Docker resources outside the project |
| Isolation | enabling `privileged`, adding undeclared capabilities, weakening security options, joining host or foreign namespaces, or changing the runtime |
| Docker control plane | operating on containers, networks, or volumes outside the Compose project |
| Proxy authority | creating or controlling services that have direct access to the upstream Docker socket |

The proxy also restricts Docker-specific network exposure, including host networking, undeclared network attachments, and host port bindings not authorized by Compose.

## Out of scope

**General outbound network access.** A container may contact the LAN or Internet through its authorized network. Restricting destinations requires a firewall, network policy, or egress proxy. Docker-specific changes to network exposure remain subject to this proxy's policy.

**Resource exhaustion.** CPU, memory, shared memory, PID limits, file-descriptor limits, restart policy, logging configuration, and similar availability controls are forwarded without comparison against Compose. The proxy does not attempt to determine whether one resource configuration is safer than another.

The proxy also does not restrict what an authorized command does within its container. Any access granted to the service remains available to that command.

## Field classification

Docker request fields are classified by their security effects.

| Class | Meaning | Policy action |
| --- | --- | --- |
| A | Can widen host confidentiality, host integrity, or isolation | Compare with Compose or refuse |
| B | Can add Docker-specific network exposure | Compare with Compose |
| C | Affects availability or resource consumption | Forward |
| D | Affects container-local behavior, lifecycle, or general network behavior | Forward |
| E | Security impact cannot be bounded cheaply | Refuse, or exact-match when Compose can express the value |

Classification depends on a field's effects, not simply on whether Compose has a corresponding setting.

Host-dependent values such as storage drivers, runtimes, and plugins are not assumed safe. When Compose can express them, the proxy compares them exactly instead of trying to determine which value is less permissive.

See [policy.md](policy.md) for the comparison rules and `internal/policy/inventory_test.go` for the field inventory.

## Fail-closed behavior

Requests are denied unless an explicit rule authorizes them. Unknown endpoints, unsupported API versions, and operations without an authorization rule are refused. List requests must also be scoped to authorized resources.

Request bodies are decoded strictly, so unknown fields are rejected. The field inventory tests require every field in the Docker request structures used by the policy to be classified. A Moby dependency update that introduces an unclassified field therefore fails tests until the field is reviewed.

### Denial messages

Denial messages balance diagnostic usefulness with unnecessary information disclosure.

Configuration mismatches may report the relevant field and the expected and actual values. This helps legitimate users diagnose failures and report them to administrators.

A protected-service denial identifies the service as protected without explaining the classification criteria. Other denial messages should not unnecessarily reveal information about resources outside the authorized Compose project.

These restrictions reduce unnecessary information disclosure but are not relied upon for authorization security.

## Container creation and control

Container creation is limited to one-off containers, as used by `docker compose run`. Existing service containers may be started and stopped, but cannot be created or otherwise controlled through the restricted socket. Read-only operations remain available when the container passes the ownership and configuration checks.

One-off containers are identified by `com.docker.compose.oneoff=True`. This label is client-controlled and does not prove that Docker Compose made the request. The container must still match a declared Compose service. The label does not limit how long a container may run.

The `--allow-command` setting controls which supported operations are available to clients of the socket. It applies to all clients equally and does not authenticate them. It cannot bypass the Compose configuration or the protected-service restrictions.

See [policy.md](policy.md) for the supported commands, their Docker API operations, and the authorization rules.

## Existing-container ownership

An existing container is authorized only when both its project identity and security-sensitive configuration match the resolved Compose project.

The proxy requires a matching project label, a declared service label, and the security settings that can be verified from the Engine's inspect result. Labels alone are insufficient because another client may create a container carrying the same labels. Matching configuration alone is insufficient because another project may legitimately use the same settings.

The proxy obtains this information from the Engine rather than maintaining its own ownership database. A client cannot choose a different service for an existing-container operation by supplying labels in that request.

Docker normalizes some container settings after creation, so inspect results cannot reconstruct every original request field. Inspect-mode comparison skips checks whose original values cannot be reliably recovered. Consequently, authorization of an existing container does not prove that its original create request would pass the current policy.

Containers should be recreated after security-sensitive Compose settings change.

## Protected services

A service with direct access to the upstream Docker socket can bypass the proxy entirely. Such services are **protected**: the proxy refuses to create or control their containers, even when the requested configuration matches Compose. Read-only operations remain available subject to the usual ownership checks.

A service is protected when any resolved Compose mount satisfies:

```text
Type == bind
AND Destination == dockerHost
AND Source != restrictedSocket
```

Here, `dockerHost` is the upstream socket path configured by `--docker-host`, and `restrictedSocket` is the proxy's listening socket configured by `--listen`. The comparison uses the configured paths rather than assuming a fixed Docker socket location.

Resolved mounts include bind mounts generated from file-backed Compose `secrets:` and `configs:`. Read-only access to the upstream socket is still direct Docker access and does not exempt a service from protection.

The source exception allows an application to mount the restricted socket at the Docker socket path without becoming protected.

Protection is determined from the Compose definition, including its resolved mounts. The proxy does not inspect the host filesystem to discover other ways a container might reach the Docker Engine.

### Detection limitations

The protected-service rule does not detect:

- a parent directory mount containing the socket;
- access through symlinks;
- a Docker socket mounted at a different container path;
- Docker API access over TCP or SSH;
- host access exposed through a custom volume driver or another mechanism not represented by the checked bind mount.

The rule also does not verify that a bind source is actually a Docker socket. Mounting an unrelated file at the configured Docker socket destination still makes the service protected.

These limitations mean the rule cannot guarantee that every service with Docker Engine access is detected. Operators must review the Compose configuration for other paths to Docker access.

## Policy lifetime

The proxy resolves its Compose project, protected services, and seccomp profiles at startup. The allowed command set is also fixed at startup.

Changing the Compose definition or `--allow-command` does not update an already-running proxy. The proxy must be restarted for the new policy to take effect.
