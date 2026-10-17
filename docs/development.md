# Development and maintenance

Build, test, and maintenance notes for `compose-policy-proxy`.

## Checks

```console
go build ./...
go vet ./...
golangci-lint run
go test -race ./...
```

Check formatting with `gofmt -l .`. CI runs lint, tests, and a multi-platform image build; see `.github/workflows/ci.yml`.

The tests in `test/e2e` exercise a real Docker Engine and Compose CLI. They skip if Docker is unavailable. The Engine must also be able to access the test project directory at the same absolute path for bind mounts; this can be an issue with remote or VM-backed engines. CI runs E2E on GitHub-hosted Linux runners.

## Package responsibilities

| Package | Responsibility |
| --- | --- |
| `internal/policy` | Compose-based authorization, protected services, command permissions, Docker API allowlist, comparisons, and request scoping |
| `internal/proxy` | HTTP transport, streaming, denial responses, and decision logging |
| `internal/compose` | Loading and resolving the Compose project |
| `internal/engine` | Read-only Engine inspection and API version queries used by authorization |

Authorization rules belong in `internal/policy`, not the proxy transport. List filters are rewritten only when the policy authorizes the rewritten scope. The proxy also adjusts Engine API negotiation responses to the validated API version.

## Maintaining the policy

The API allowlist is deny-by-default and lives in `internal/policy/routes.go`. New endpoints require explicit authorization rules. Review whether each operation can affect resources outside the project, how resource ownership is established, whether list results need scoping, and whether transport requires special handling. Protected services must not be created, controlled, or interacted with; read-only inspection remains available where authorized. This also applies when the request names an indirect resource, such as an exec ID rather than a container ID.

`internal/policy/inventory_test.go` classifies Docker request fields as compared, refused, or forwarded. Dependency upgrades must not add a security-sensitive field without an explicit decision. `TestEveryRequestFieldIsClassified`, `TestClassificationCoversTheCreateRequestShape`, and `TestEveryAllowlistedEndpointHasARule` guard against omissions. The rationale and exact rules belong in [security-model.md](security-model.md) and [policy.md](policy.md), not in duplicated documentation here.

When changing container-create comparison, review inspect-mode behavior too. The Engine may normalize settings or fill in defaults; an inspect relaxation should allow those defaults without accepting real privilege differences. The proxy must continue to resolve protected services before permitting a state-changing operation.

### Docker and Compose upgrades

The policy follows Compose semantics, not a particular serialized request. When clients change their wire representation, capture actual Docker API traffic before adding equivalence rules, especially for mounts and list filters. Do not broaden canonicalization just to make a test pass.

The following depend on observed upstream behavior and should be revisited on upgrades:

| Area | Assumption to verify |
| --- | --- |
| `HostConfig.ContainerIDFile` | May write to a host path, even when the Engine currently ignores it |
| `Config.OnBuild` | Cannot execute while build/commit endpoints are denied |
| `Config.ArgsEscaped` | Linux daemon over a Unix socket |
| `HostConfig.Links` | Adds naming, not network reachability |
| `Config.ExposedPorts` | Does not bind a host port without `PortBindings` or `PublishAllPorts` |
| Mount representations | Equivalent mounts may appear in `Binds`, `Mounts`, or `Tmpfs` |
| Inspect defaults | Normalized fields do not create false policy mismatches |
| Exec inspect | `ProcessConfig` reports privilege and effective user; omitted privilege fields fail closed |
| List filters | Engine's regex/name and label filter semantics remain as expected |
| Container rename | `up` creates a container under a temporary name, then renames it to the `container_name` of the service, or to `<project>-<service>-<number>` |
| Network identifiers | `down` inspects and removes a network by the identifier the Engine assigned, not by its name |
| Network labels | Compose writes `com.docker.compose.network=<key>` on every network it creates, and matches a project label plus that key before removing one |
| Service container labels | `up` labels a service container `com.docker.compose.oneoff=False` and `com.docker.compose.container-number` |

## Building the container image

Images are built with [ko](https://ko.build), without a Dockerfile. The executable is `./cmd/compose-policy-proxy` and the release image is published for `linux/amd64` and `linux/arm64`. `--image-user 0:0` allows access to a typical root-owned Docker socket; the proxy creates its listening socket directory at startup. `ko` builds the binary statically (`CGO_ENABLED=0`).

Build locally:

```console
ko build ./cmd/compose-policy-proxy --bare --local --image-user 0:0
```

Verify the multi-platform build in an OCI layout:

```console
ko build ./cmd/compose-policy-proxy --bare --platform=linux/amd64,linux/arm64 \
  --image-user 0:0 --push=false --sbom none --oci-layout-path /tmp/ko-layout
```

CI and release builds use `ko-build/setup-ko@v0.8` to install ko. The action version is not the ko version.

## Releasing

The Git tag is the release version; no source file needs updating. A tag push runs `.github/workflows/release.yml`, which publishes images to GHCR under the version tag and `latest`, and embeds the version and commit using linker flags.

```console
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Verify the published image:

```console
docker pull ghcr.io/hnw/compose-policy-proxy:v0.1.0
docker run --rm ghcr.io/hnw/compose-policy-proxy:v0.1.0 --version
docker buildx imagetools inspect ghcr.io/hnw/compose-policy-proxy:v0.1.0
```

Replace `v0.1.0` with the release tag. `--version` reports `dev` in local builds without linker-injected version information. The workflow does not create a GitHub Release or perform post-publish verification. For the first public release, make the GHCR package public in its package settings.
