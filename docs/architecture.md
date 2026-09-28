# Architecture

This document describes how `openshell-driver-lxd` is put together: the
workspace's crates, the request flow through them, and the subsystems that
back a sandbox's lifecycle (image conversion, boundary injection, networking,
event watching, and clean-up).

## Overview

`openshell-driver-lxd` is an out-of-tree compute driver for
[OpenShell](https://github.com/NVIDIA/OpenShell). OpenShell's gateway
delegates sandbox lifecycle management to a pluggable driver over gRPC; this
driver implements that contract (`compute_driver.proto`) and realizes
sandboxes as LXD/Incus system containers, talking to LXD over its REST API.

```
 ┌─────────────────┐   gRPC over Unix socket   ┌──────────────────────┐   REST (Unix socket    ┌──────────┐
 │  OpenShell       │ ───────────────────────▶ │ openshell-driver-lxd │ ─  or HTTPS+mTLS)  ───▶ │   LXD    │
 │  gateway         │ ◀─────────────────────── │ (this repo)          │ ◀───────────────────── │ (daemon) │
 └─────────────────┘   ComputeDriver service    └──────────────────────┘                        └──────────┘
                                                          │
                                                          ▼
                                                 sandbox = two LXD instances
```

## A sandbox is two containers

OpenShell v0.1.0 (RFC 0012) split the monolithic supervisor in two, and the
driver provisions both halves:

```
                       ┌──────────────────────────────────────┐
     gateway  ◀──mTLS──▶│ <name>-supervisor                    │  the trusted half
                       │   openshell-supervisor               │  holds the gateway
                       │   --backend-descriptor-file          │  credentials and the
                       │   --auth-bundle-file                 │  main-process spec
                       └───────────────────┬──────────────────┘
                                           │ Sandbox Protocol
                                           │ TLS over TCP, pinned per launch
                       ┌───────────────────▼──────────────────┐
                       │ <name>                               │  the untrusted half
                       │   openshell-sandbox --bootstrap      │  the user's image,
                       │   (PID 1, then the workload)         │  and nothing the
                       └──────────────────────────────────────┘  workload may not see
```

Only the workload instance is a sandbox as far as the gateway is concerned:
every driver query filters the companion out by `user.openshell.role`, so a
caller still sees one sandbox per sandbox. The companion's own state is folded
into the sandbox's `Ready` condition, which is the only way it is visible at
all.

The gateway's `launch_authentication` is **split, never minted**: the companion
gets the supervisor bundle verbatim, the workload gets only the gateway
identity and the public verification keys. The supervisor's bearer tokens
never reach the untrusted half.

The gateway connects to the driver's Unix domain socket (default
`/var/run/openshell-driver.sock`) at startup and drives the sandbox lifecycle
(`create`, `start`, `stop`, `delete`, `watch`) through the
`openshell.compute.v1.ComputeDriver` service. The driver, in turn, is an LXD
REST API client: it can talk to a local snap over a Unix socket or to a
remote/clustered LXD over HTTPS with mutual TLS.

## Workspace layout

The Cargo workspace has three crates, each with a single responsibility:

| Crate | Role |
|---|---|
| `computev1` | Generates the tonic/prost gRPC bindings from the vendored `compute_driver.proto` (see `proto/`). No hand-written logic beyond `build.rs`. |
| `lxd-client` | A general-purpose async HTTP client for the LXD REST API. Transport-agnostic (Unix socket or HTTPS+mTLS) and driver-agnostic — it knows nothing about OpenShell or sandboxes. |
| `openshell-driver-lxd` | The driver itself: the binary, the gRPC service implementation, and the OpenShell↔LXD translation and orchestration logic. |

### `computev1`

`build.rs` runs `tonic-prost-build` against `proto/compute_driver.proto` at
compile time and generates the `ComputeDriver` server/client traits and
message types under `computev1::pb`. The proto file is vendored from
upstream OpenShell (Apache-2.0, see `proto/README.md` and
`THIRD-PARTY-NOTICES`) and refreshed with `make sync-proto`.

### `lxd-client`

A standalone, reusable LXD API client (see `crates/lxd-client/README.md`).
Key modules:

- `client.rs` — `LxdClient`, request signing/transport setup, project scoping.
- `instances.rs` — instance CRUD, start/stop, state, file push.
- `operations.rs` — waits for LXD's async operations to complete, preferring
  a WebSocket subscription to `/1.0/events?type=operation` with a REST
  long-poll fallback, and reconciling on reconnect to close the
  subscribe/check race.
- `events.rs` — subscribes to LXD's lifecycle event WebSocket and exposes it
  as a `Stream`.
- `networks.rs`, `acls.rs` — network lookups and idempotent network ACL
  management.
- `storage.rs` — custom storage volumes (used for the supervisor and DHCP
  client binaries) and image import into a storage pool.
- `resources.rs` — Kubernetes-style CPU/memory quantity conversion to LXD's
  `limits.cpu`/`limits.memory`.
- `split_image_body.rs` — streams a large image tarball as a multipart body
  LXD accepts, without buffering it all in memory.

All fallible calls return `Result<_, LxdError>`, distinguishing API errors,
failed async operations, transport errors, and TLS setup errors.

### `openshell-driver-lxd`

The driver binary and library. `main.rs` is thin: it parses configuration,
validates it (see below), binds the gRPC Unix socket, and constructs the
service. The rest of the logic lives in `lib.rs`'s modules:

| Module | Responsibility |
|---|---|
| `config.rs` | `Config`: the CLI/env schema (`clap`), defaults, and cross-field validation (e.g. plaintext gateway must be opted into explicitly). |
| `driver.rs` | `LxdComputeDriver`: the core orchestration logic for every sandbox operation, independent of gRPC. |
| `grpc.rs` | `ComputeDriverService`: thin tonic trait implementation that maps proto requests to `LxdComputeDriver` calls and `DriverError` to `tonic::Status`. Also owns the `WatchSandboxes` event fan-out. |
| `mapping.rs` | Pure translation between the proto's `DriverSandbox`/`DriverSandboxTemplate` shapes and LXD's instance config/devices/profiles shapes. |
| `image.rs` | OCI→LXD image resolution, conversion, and caching (`ImageCache`, `SkopeoImporter`), and supervisor binary extraction. |
| `gc.rs` | Clean-up of stale images, storage volumes, and scratch directories the driver no longer needs. |
| `watcher.rs` | Subscribes to LXD lifecycle events and turns them into `WatchSandboxes` updates, deduplicating clustered LXD's duplicate delivery. |
| `egress.rs` | Builds the network ACL rules that confine a sandbox's egress to the gateway and the public internet. |
| `dhcp_client.rs` | Locates/validates the static `busybox`/`udhcpc` binary injected into every sandbox to configure its network interface. |
| `error.rs` | `DriverError` and its mapping to gRPC status codes. |

## Request flow

`ComputeDriverService` (in `grpc.rs`) implements the `ComputeDriver` trait
generated by `computev1`. Each RPC is a thin wrapper: it resolves the target
instance name (by `sandbox_name`, or by looking up
`user.openshell.sandbox_id` when only `sandbox_id` is given — see
`resolve_name`), delegates to the matching `LxdComputeDriver` method, and
converts `DriverError` into a `tonic::Status`.

`LxdComputeDriver` (in `driver.rs`) holds:

- the driver `Config`;
- an `LxdClient` scoped to the configured project;
- an `ImageCache` for OCI→LXD image resolution;
- per-key async locks for supervisor/DHCP-client volume provisioning and
  per-instance lifecycle operations (so concurrent requests for the same
  sandbox or the same digest-keyed volume serialize instead of racing);
- a `RwLock` (`volume_use`) held shared while a sandbox's auxiliary volumes
  are being provisioned and used, and exclusively by garbage collection —
  this prevents GC from deleting a volume between its creation and first use;
- a once-resolved `PlacementDefaults` cache (network/storage pool a sandbox
  lands on when the request names neither), read from the project's
  `default` LXD profile on first use.

### `create_sandbox`

1. Validate the request (`validate_sandbox_create`).
2. Resolve placement (network, storage pool) via `mapping::Placement`,
   falling back to the cached project defaults.
3. Translate the sandbox spec/template into LXD instance config
   (`mapping::build_create_config`): environment variables, the encoded main
   process spec (`ENV_MAIN_PROCESS_SPEC`), resource limits, PID limits, and
   (optionally) `security.nesting`.
4. If restricted egress is enabled, ensure a network ACL exists confining the
   sandbox NIC to the gateway endpoint and the public internet
   (`egress.rs`).
5. Resolve the sandbox rootfs image, importing/converting it on demand if not
   already cached (`image::ImageCache::resolve_alias`).
6. Resolve the supervisor binary (either a configured host path or extracted
   on demand from the supervisor OCI image) and the DHCP client binary, and
   ensure each is materialized as a digest-keyed LXD custom storage volume
   (`ensure_supervisor_volume` / `ensure_dhcp_client_volume`), so the same
   binary is reused by every sandbox rather than duplicated per instance.
7. Build the instance's devices (`mapping::build_create_devices`): NIC, the
   supervisor/DHCP-client volumes mounted read-only, and a GPU passthrough
   device if requested.
8. Create the LXD instance **stopped**, wait for the operation, then push the
   sandbox token and (if configured) gateway TLS materials directly into the
   guest's rootfs — before the supervisor's init ever runs, avoiding a race
   where it reads them too early.
9. Start the instance and let it settle (`settle_after_start`); on any
   post-create failure, the instance is stopped and deleted so a failed
   create leaves nothing behind.

### `start_sandbox` / `stop_sandbox` / `delete_sandbox`

`start_sandbox` re-pushes TLS materials (so a restarted sandbox picks up
rotated ones) and clears the "stopped on request" marker before starting, so
a sandbox that later exits on its own is reported as `ContainerExited` rather
than as user-stopped — restoring the marker if the start itself fails.
`stop_sandbox` treats "already stopped" (from LXD) as success. `delete_sandbox`
stops (if needed) then deletes the instance, and returns the sandbox's
`sandbox_id` so the gateway can be told which sandbox is gone even though its
name is no longer resolvable afterwards. All three are guarded per-instance by
`instance_lifecycle_lock` to avoid overlapping start/stop/delete races on the
same name.

### `watch_sandboxes`

`ComputeDriverService::new` spawns a background task (`watcher::spawn`) that
subscribes to LXD's lifecycle event stream and publishes `WatchEvent`s on a
`tokio::sync::broadcast` channel, re-subscribing after a delay if the stream
drops (e.g. across a snap refresh). Each `watch_sandboxes` call first sends a
snapshot of every currently managed sandbox, then forwards live events from
the broadcast channel — preserving relative order so, for instance, an exit
snapshot can never be delivered after that sandbox's deletion event. The
watcher deduplicates the double delivery clustered LXD is observed to send
for a single lifecycle action.

## Image handling

Sandboxes run from LXD images produced by converting an OCI/Docker image
on demand (`image.rs`, `SkopeoImporter`):

1. `skopeo copy` pulls the OCI image (subject to `--allowed-registries`).
2. `umoci unpack` extracts its rootfs.
3. The bundled POSIX init script (`assets/openshell-init.sh`) is injected at
   `/openshell-init.sh` and pointed to by `/sbin/init`, since LXD containers
   have no dedicated "init command" instance option — this lets a sandbox
   boot even inside a restricted project that forbids `raw.lxc`.
   See [The workload half's boot path](#the-workload-halfs-boot-path) for why
   that script runs nothing out of the image it is injected into.
4. `mksquashfs` builds the rootfs squashfs and a `metadata.tar.xz` is built
   with `tar`/`xz`, forming an LXD unified image tarball.
5. The image is imported into LXD and aliased by a prefix
   (`openshell-oci-`) plus a conversion revision and the content digest
   (`CONVERSION_REVISION`), so a change to the conversion process (e.g. the
   init script) invalidates every previously cached image without touching
   unrelated ones.

`ImageCache` deduplicates concurrent resolution of the same reference and
serves already-converted images by alias without re-pulling. The supervisor
binary (`/openshell-sandbox`) is extracted the same way from a separate,
minimal "supervisor" OCI image, cached on the host by content digest, and
uploaded once per digest as an LXD custom storage volume that every sandbox
mounts read-only — the sandbox rootfs and the supervisor binary are
versioned and distributed independently.

Garbage collection (`gc.rs`) periodically removes:

- driver-managed images tagged with an older `CONVERSION_REVISION`;
- current-revision images unused for longer than the configured retention
  (except the default image's, which every image-less create needs);
- supervisor/DHCP-client storage volumes for digests no longer in use;
- host-side supervisor binary caches for other digests;
- stale scratch directories left behind by an interrupted import.

It only touches objects in the driver's own LXD project, and only ones
carrying the driver's own alias/name conventions.

## Networking and egress

Both of a sandbox's containers get a NIC on the resolved network, and the
driver attaches an LXD network ACL (`egress.rs`) to each, allowing only:

- outbound TCP to the resolved gateway endpoint, and
- outbound traffic to public internet addresses (the complement of
  private/reserved IPv4 ranges and IPv6 unique-local/link-local/loopback
  space),

with everything else — including inbound, except return traffic tracked by
allowed connections — rejected. DNS needs no explicit rule: LXD lets an OVN
NIC reach the network's own DNS resolvers regardless of ACLs. This confines
the containers as a whole (beyond the boundary's own in-guest policy proxy)
from reaching the LAN, the LXD host, or other sandboxes.

**This ACL is not optional, and it is why sandboxes need an OVN network.**
From OpenShell v0.1.0 it is the sandbox's *outer network fence*: the driver
projects it into the four guarantees upstream requires — default-deny egress,
no unmanaged egress path, verified revocation, and failing closed if the
controller is lost (`isolation.rs`) — and both halves of a sandbox validate
that projection before the workload runs. A sandbox the driver cannot fence is
a sandbox that never attaches, so `create_sandbox` refuses one up front.

LXD only applies `security.acls` to an individual NIC on an OVN network; a
bridge accepts an ACL on the network itself but not per-NIC, which is not a
per-sandbox fence. So `create_sandbox` fails with `FailedPrecondition` on a
bridge rather than provisioning a sandbox that cannot start.

Inside the guest, network configuration is done by a static `busybox`/`udhcpc`
binary (`dhcp_client.rs`) run against an event script
(`assets/dhcp-client/udhcpc.script`), injected the same way as the boundary
binary — as a digest-keyed read-only storage volume — so no DHCP client needs
to be baked into the sandbox image itself.

The workload must acquire its address before the companion can be told where
to dial it, which is why create starts the workload first, waits for DHCP, and
only then writes the companion's backend descriptor and starts it.

### The workload half's boot path

The workload container's rootfs is the user's own image, and the container's
init is root inside it. Anything that init took *from* that image would
therefore be the image's own code, running as root, before the boundary has
dropped privilege — and it could replace the drop, or the boundary, with
whatever it liked. The boundary is what reports the sandbox's confinement to
the companion, so an image able to substitute it could report any confinement
it wanted while having none.

Podman, Docker and Kubernetes avoid this by having the runtime exec the
boundary directly as the container's first process, with the identity and the
capability set already applied. LXD has no equivalent instance option, so the
init script reaches the same guarantee by naming everything explicitly:

- its interpreter is the static busybox on the driver's own volume, named in
  the script's `#!` line, not the image's `/bin/sh`;
- every program it runs before handing over — `ip`, `awk`, `sed`, `grep`,
  `hostname`, the DHCP client and its event script — is an absolute path on
  that volume;
- and the privilege drop is not a `setpriv` from the image but the driver's
  own boundary binary, invoked as
  `openshell-sandbox launch-capability-free <uid> <gid> <bootstrap> /sandbox`.
  That subcommand — the one upstream's Podman driver uses for the same job —
  chowns the workspace, empties every capability set, sets `no_new_privs` and
  changes all three uid and gid triples, in the driver's own trusted code,
  before it reads anything the workload could have written.

Because that drop clears the supplementary group set outright, and the
boundary then checks what it is running as against what the driver declared,
the resolved identity never carries supplementary groups — see
`isolation.rs::resolve_workload_identity`.

The supervisor companion's rootfs is the driver's own supervisor image rather
than the user's, so its half of the script may use what that image ships,
including `curl` and the dynamic loader.

## Configuration and safety gates

`config.rs` defines the CLI/env schema (`clap::Parser`) with defaults for the
gRPC socket path, LXD endpoint, default sandbox/supervisor images, PID limits,
timeouts, and clean-up intervals. `main.rs` performs fail-fast checks before
accepting any gRPC connection:

- refuses to serve sandboxes over a plaintext gateway connection unless
  `--allow-plaintext-gateway` is explicitly set, and validates the sandbox
  TLS material is readable when TLS is configured;
- checks the default and supervisor images against `--allowed-registries` so
  a misconfigured allowlist is caught at start-up rather than on first
  `create_sandbox`;
- validates `--supervisor-bin`, if given, is an executable regular file;
- verifies the configured LXD project exists and the LXD server supports the
  host architecture;
- resolves placement defaults once, and pre-warms the default sandbox image
  in the background (a cold import can take minutes; the socket accepts
  connections immediately, and a `create_sandbox` racing the pre-warm waits
  on the same in-flight import rather than starting a second one).

## Packaging

The driver is distributed as part of two OCI "rock" images built with
Rockcraft (`.github/workflows/rock.yaml`):

- `rockcraft.yaml` (base `ubuntu@26.04`) bundles the upstream OpenShell
  gateway and this driver under Pebble, plus the host tools the image
  conversion pipeline shells out to (`skopeo`, `umoci`, `squashfs-tools`,
  `xz-utils`), published as `ghcr.io/canonical/openshell-gateway`.
- `rocks/supervisor/rockcraft.yaml` (base `bare`) builds only the static,
  musl-linked `openshell-sandbox` boundary binary from the *same pinned
  upstream commit* as the gateway rock, published as
  `ghcr.io/canonical/openshell-supervisor`. Pinning both to one revision is
  what makes a supervisor/gateway version mismatch impossible rather than
  merely unlikely — a mismatch can otherwise fail to sync policy and exit.

Both rocks are smoke-tested on every push/PR to `main`
(`tests/rock/smoke.sh`, `tests/rock/smoke-supervisor.sh`).

## Testing

- `make test` provisions a local LXD (`scripts/setup-lxd-test-env.sh`) and
  runs `cargo test --workspace`, including `lxd-client`'s integration tests
  against a real daemon.
- `make test-conformance` runs upstream OpenShell's conformance suite against
  the driver (`scripts/conformance.sh`, environment in
  `scripts/openshell-env.sh`).
- `make test-upstream-e2e` runs upstream's policy, Landlock, and inference
  end-to-end tests against the driver (`scripts/upstream-e2e.sh`).
