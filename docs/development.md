# Development and maintenance

This document covers build, test, and policy-maintenance work for `compose-policy-proxy`.

## Basic checks

```console
go build ./...
go vet ./...
gofmt -w .
golangci-lint run
go test -race ./...
```

`.github/workflows/ci.yml` has three jobs on pull requests and pushes to `main`: `lint` runs the formatting check, `go vet` and golangci-lint, `test` runs `go test -race ./...`, and `image` builds the container image for both platforms. The `gofmt` step fails rather than rewrites, so a formatting difference is reported instead of silently committed by the formatter.

### End-to-end tests

The repository contains end-to-end tests under `test/e2e` that drive real `docker compose run` traffic through the proxy against a Docker Engine. They skip when the required Engine or Compose plugin is unavailable.

E2E runs also depend on the project directory being bind-mountable by the Docker host. Relative bind mounts resolve to the project's absolute host path, so a test environment where that path is not visible to the Engine cannot validate the intended behavior correctly.

The end-to-end tests run inside the `test` job, on GitHub-hosted Linux runners where Docker shares the runner's filesystem and the checkout path is therefore visible to the Engine. A remote or VM-based Docker daemon that does not mount the checkout directory will make them skip or fail for reasons unrelated to the code.

## Package responsibilities

One decision, one place:

| Package | Responsibility |
| --- | --- |
| `internal/policy` | every authorization decision: the Compose project, the protected services, the Docker API allowlist and API versions, request decoding, service matching, ownership of existing containers, and the images, networks and volumes the project declares |
| `internal/proxy` | transport: HTTP handling, forwarding, streaming and connection hijacking, the denial response, and the decision log |
| `internal/compose` | loading and resolving the Compose project, and deriving the protected services from its mounts |
| `internal/engine` | the read-only Docker Engine queries authorization needs, and the API versions startup is checked against |

`Policy.Authorize` is the whole of a decision. The proxy keeps no policy state of its own: if the proxy has to know a rule to decide, that rule is in the wrong package. The one thing the proxy does change about a request is the list filter the policy pinned, which [policy.md](policy.md) describes. The only responses it changes are the two API negotiation answers.

## Policy source of truth

`internal/policy/inventory_test.go` classifies the Docker request structures used by the proxy. Every relevant field must be explicitly classified as compared, refused or forwarded, with a short reason. This prevents a newly introduced Docker field from becoming allowed merely because no comparison code references it yet.

Human-readable rationale belongs in [security-model.md](security-model.md) and [policy.md](policy.md). The inventory test remains the machine-checked source of truth for field coverage.

## Upgrading the Moby dependency

A Moby version bump can change the policy surface even if the proxy code itself does not change.

Run the full test suite and pay particular attention to these checks:

- `TestEveryRequestFieldIsClassified` fails in both directions: a Docker request struct that gained a field has no policy decision for it, and a classified field that no longer exists in the Moby types is a leftover.
- `TestClassificationCoversTheCreateRequestShape` fails when `container.CreateRequest` gains or loses a top-level field.

Comparison behavior is verified by outcome-based tests rather than by searching source code for field names. A dependency bump should not be merged by merely updating the inventory until each new or changed field has been reviewed against the security model.

## Fields worth re-checking on Docker upgrades

Some current decisions depend on observed Engine or Compose behavior and deserve explicit review when those components change.

| Area | Why to re-check |
| --- | --- |
| `HostConfig.ContainerIDFile` | currently refused because its API meaning is a host-path write even though current Engine behavior may ignore it |
| `Config.OnBuild` | safe to forward only while build/commit endpoints remain outside the allowlist |
| `Config.ArgsEscaped` | classification assumes the proxy talks to a Linux daemon over a Unix socket |
| `HostConfig.Links` | classification assumes links add naming behavior rather than new network reachability |
| `Config.ExposedPorts` | classification assumes it cannot create a host listener without `PortBindings` or `PublishAllPorts` |
| mount representations | Compose-aware clients may change whether they use `Binds`, `Mounts`, `Tmpfs`, or another representation |
| inspect defaults | daemon-normalized fields may change across Engine versions |
| list filters | the Engine matches `name` as a regular expression and `label` key by key; a change in either is a change in what a scoped list can return |

## Compatibility testing

The policy is defined by Compose semantics, not by one fixed Docker Compose wire encoding. When a Compose or client upgrade changes Docker API serialization, determine whether the new request is:

- semantically equivalent to an already supported Compose request;
- a new capability that should be compared or refused; or
- a field outside the security boundary that should be forwarded.

Do not widen canonicalization merely to make a new test pass. Add an equivalence only when the alternate representation is understood and preserves the same policy meaning. For mounts in particular, keep tests for the representations actually emitted by Compose-aware clients.

When real Compose traffic changes shape, record it with a recording proxy in front of the Engine rather than by reasoning from the source. The pinned name filter in `internal/policy/scope.go` exists because the request Compose actually sends does not say what it appears to say.

## Existing-container checks

Changes to create-time policy should be reviewed together with `compareContainer` and inspect-mode behavior. Inspect results contain daemon-assigned defaults, so some create-time checks cannot be repeated literally; inspect mode may skip only those whose original requested value cannot be reconstructed reliably.

When adding a new inspect relaxation, add tests for both directions: a legitimate daemon-added or normalized value is accepted, and a real security-sensitive difference is still rejected.

## Authorization and allowlist changes

The Docker API allowlist is deny-by-default and lives with authorization, in `internal/policy/routes.go`. It is pinned by tests. Adding an endpoint is a policy change, not just a routing change, so review:

- whether the endpoint can mutate or reveal resources outside the project;
- how target ownership is proven;
- whether list operations need filter scoping;
- whether the endpoint introduces a new Docker capability not represented by the current field policy;
- whether streaming, hijacking, or long-lived connections require special proxy handling.

Joining the allowlist does not authorize an operation: an endpoint with no decision rule of its own is refused, which `TestEveryAllowlistedEndpointHasARule` enforces.

## Protected-container impact of a new endpoint

The policy guarantees this invariant:

> A client may inspect a protected container where the existing policy permits it, but must not create, modify, control, or interact with that container through the proxy.

A protected service holds the Docker socket itself, so any endpoint that can act on its containers is an endpoint back around the proxy. Review that for every new Docker API endpoint, including ones that are not under `/containers/`: a hypothetical prune, a network connect, or a commit that names a container would each reopen the boundary.

The check is mechanical. `readOnlyOperations` in `internal/policy/routes.go` names the only allowlisted container operations that may act on a protected container; every other one is control, so a new endpoint is refused for a protected container without having to be classified, and `TestReadOnlyOperationsAreAllowlisted` catches a stale entry.

New support for Compose workflows such as `up`, `down`, or `exec` should be introduced by tracing the real Docker API traffic produced by the supported client and extending the allowlist only for the operations that workflow actually needs.

## Container image

The image is built with [ko](https://ko.build), which compiles the binary and assembles a container image in one step. There is no Dockerfile and no build context: ko reads the Go module directly, so the image cannot drift out of step with the source the way a copied-in binary can.

The repository has no .ko.yaml, so ko uses its default base image.

Build locally:

```console
ko build ./cmd/compose-policy-proxy --bare --local \
  --platform=linux/amd64,linux/arm64 --image-user 0:0
```

Constraints to preserve in any change to the image:

- **ko builds with `CGO_ENABLED=0`**, which is what makes the binary static, which is what lets it run on a base with no libc.
- **`--image-user 0:0`.** The proxy runs as root because the Docker socket is `root:root 0660` on most hosts and a non-root process cannot open it.
- **The import path is `./cmd/compose-policy-proxy`**, not `.`: ko needs a `main` package, and this repository keeps the entrypoint under `cmd/`.
- **ko has no `CMD` flag.** The binary's own `--listen` default is `/run/compose-policy-proxy/docker.sock`, which is what the image needs.
- **ko cannot create directories**, so nothing prepares `/run/compose-policy-proxy`; the process creates it at startup and a mounted volume supplies it in practice.
- **`--local` and `--oci-layout-path` cannot be combined**, so the CI image job builds to an OCI layout instead.

### Verifying a multi-platform build

```console
ko build ./cmd/compose-policy-proxy --bare --platform=linux/amd64,linux/arm64 \
  --image-user 0:0 --push=false --sbom none --oci-layout-path /tmp/ko-layout
```

Then read the platforms out of the layout. A manifest list missing an architecture is otherwise invisible until somebody runs on that platform.

### Versions in the built image

ko takes its build flags from the command line, so a release build passes everything it needs at once:

```console
KO_DOCKER_REPO=ghcr.io/hnw/compose-policy-proxy \
ko build ./cmd/compose-policy-proxy --bare --platform=linux/amd64,linux/arm64 \
  --image-user 0:0 \
  --ldflags="-s -w -X main.version=v0.1.0 -X main.commit=$(git rev-parse HEAD)" \
  --tags v0.1.0,latest --push
```

The Git tag is passed through verbatim, so `--version` reports exactly the tag that triggered the build. A plain `go build` reports `compose-policy-proxy dev`, without claiming a release version: the ldflags are the only thing that injects one.

The workflows use `ko-build/setup-ko@v0.8`, which is the version of the action, not of ko. The action installs ko's latest release, because the workflows set no `version` input, so `--ldflags` support follows the installed ko rather than a pinned release.

## Release process

The Git tag is the single source of the release version. Nothing else needs updating when cutting a release, and no file records the version that could drift out of sync.

```console
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

That tag push triggers `release.yml`, whose single `publish` job logs in to GHCR and pushes the image as `v0.1.0` and `latest`, injecting the version and the commit through ldflags. It creates no GitHub Release and verifies nothing after the push. Both tags are the same build, so they resolve to one identical manifest list. There are no partial-version tags such as `:v0.1` or `:v0`: a version that says less than the release does is one more thing to keep correct.

Release publishing runs on version tags only, so unreleased changes cannot overwrite `:latest`. Pull requests build the image in the `image` job of `ci.yml`, which builds both platforms into an OCI layout.

### Verifying a release

```console
docker pull ghcr.io/hnw/compose-policy-proxy:v0.1.0
docker run --rm ghcr.io/hnw/compose-policy-proxy:v0.1.0 --version
docker buildx imagetools inspect ghcr.io/hnw/compose-policy-proxy:v0.1.0
```

The version line should name the tag, because the build injects it:

```text
compose-policy-proxy v0.1.0
commit: <sha>
```

The build date is not injected by the release workflow, so that line is absent.

A build without injected values reports `compose-policy-proxy dev` and omits the other lines, rather than claiming a release it does not have.

### Publishing to GHCR for the first time

GHCR requires the package to be made public once, in the repository's `Settings → Packages`. Until that is done, `docker pull` fails for anyone outside the organisation even though the workflow succeeded.
