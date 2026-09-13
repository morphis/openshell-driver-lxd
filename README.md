# openshell-driver-lxd

OpenShell Compute driver for LXD

**Status:** Early development. The core sandbox lifecycle (create/get/list/stop/start/delete,
token delivery, exec) works end-to-end against a real OpenShell gateway. A
number of features are not yet implemented — see
[Known limitations](#known-limitations) below.

## Overview

`openshell-driver-lxd` is an out-of-tree [OpenShell](https://github.com/NVIDIA/OpenShell)
compute driver backed by [LXD](https://github.com/canonical/lxd). It implements
OpenShell's `compute_driver.proto` contract and serves it over gRPC via a Unix 
domain socket, which the OpenShell gateway connects to at startup.

```
OpenShell gateway
    └── Unix socket (gRPC)
            └── openshell-driver-lxd
                    └── LXD REST API
                            └── LXD VM
```

## Demo

Creating an LXD-backed sandbox end to end — the driver and gateway logs on top,
the `openshell` CLI driving them below.

![Launching an LXD-backed OpenShell sandbox](demo.gif)

## Requirements

- Rust (stable, see `rust-toolchain.toml`)
- `protoc` (`apt install protobuf-compiler libprotobuf-dev`) for `computev1`'s proto codegen
- [LXD](https://github.com/canonical/lxd) with a storage pool and a managed network for sandboxes — `default` and `lxdbr0` unless set with `--default-storage-pool` and `--default-network` (see [Networks and Storage Pools](#networks-and-storage-pools))
- `skopeo`, `umoci`, and `mksquashfs` (`apt install skopeo umoci squashfs-tools`) — the driver uses these to pull and import sandbox OCI images into LXD on demand
- `busybox-static` or `udhcpc` (`apt install busybox-static`) — provides the fallback DHCP client for guest containers

## Quickstart

This walks through building the driver and wiring it up to a real OpenShell
gateway so you can create a sandbox end-to-end.

1. **Install and initialize LXD**, if you haven't already:

   ```sh
   sudo snap install lxd
   lxd init --auto
   ```

2. **Create the gateway's PKI.** Sandboxes connect to the gateway over
   mutual TLS, and the driver refuses to start without the materials to give
   them. The gateway release generates a CA, server and client certificates
   and the sandbox-token signing key; the server certificate must name the
   address sandboxes reach the gateway at:

   ```sh
   BRIDGE_IP="$(lxc network get lxdbr0 ipv4.address | cut -d/ -f1)"
   PKI=/tmp/openshell-pki
   openshell-gateway generate-certs --output-dir "$PKI" --server-san "$BRIDGE_IP"
   ```

3. **Build and run the driver:**

   ```sh
   make build
   ./target/debug/openshell-driver-lxd \
       --socket /tmp/openshell-driver.sock \
       --gateway-grpc-port 17670 \
       --guest-tls-ca "$PKI/ca.crt" \
       --guest-tls-cert "$PKI/client/tls.crt" \
       --guest-tls-key "$PKI/client/tls.key"
   ```

   The CA, client certificate and key are copied into every sandbox for its
   supervisor, and sandboxes are pointed at `https://<bridge address>:17670`.
   `--allow-plaintext-gateway` replaces the three TLS flags with a plaintext
   gateway, for local testing only; the repository's test environment uses
   it.

   No sandbox image needs to be pre-built or pre-loaded: the driver pulls the
   default image (`--default-image`, the upstream community
   `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`) from the
   registry and imports it into LXD on first use, caching it by content
   digest. Pass `--default-image <oci-ref>` to boot from a different image.

   The supervisor binary comes from a *separate* image
   (`--supervisor-image`, the upstream
   `ghcr.io/nvidia/openshell/supervisor:latest`) and is mounted into every
   sandbox from a storage volume. The two are deliberately distinct: the
   supervisor image ships the binary on a minimal BusyBox rootfs and cannot
   serve as a sandbox rootfs, because BusyBox's `ip` has no `netns`
   subcommand and the supervisor's proxy mode needs it to isolate the
   sandbox.

   Importing an image needs scratch space for the OCI copy plus the unpacked
   rootfs — several GiB for a real sandbox image. That scratch lives in
   `--image-work-dir` (default `/var/cache/openshell/lxd-image-work`), which
   deliberately defaults to a disk-backed path rather than `TMPDIR`/`/tmp`,
   a memory-backed tmpfs on most modern distributions.

   `--gateway-grpc-port` must match the port the gateway is told to listen on
   below — the driver uses it to construct each sandbox's `OPENSHELL_ENDPOINT`.
   A gateway that is not on the bridge needs `--gateway-endpoint` instead (see
   [Reaching the gateway](#reaching-the-gateway)).

4. **Start an OpenShell gateway pointed at the driver's socket**, using the
   out-of-tree driver flags. The gateway must be able to mint sandbox tokens
   (`gateway_jwt`), or every supervisor exits with "no sandbox token source
   available". This is for OpenShell v0.0.116 (config schema `version = 1`
   and `--drivers`; later gateways use `version = 2` and
   `--compute-driver`):

   ```sh
   cat > /tmp/openshell-gateway.toml <<EOF
   [openshell]
   version = 1

   [openshell.gateway.gateway_jwt]
   signing_key_path = "$PKI/jwt/signing.pem"
   public_key_path = "$PKI/jwt/public.pem"
   kid_path = "$PKI/jwt/kid"
   EOF

   openshell-gateway \
       --tls-cert "$PKI/server/tls.crt" \
       --tls-key "$PKI/server/tls.key" \
       --tls-client-ca "$PKI/ca.crt" \
       --enable-mtls-auth true \
       --bind-address "$BRIDGE_IP" \
       --port 17670 \
       --drivers lxd \
       --compute-driver-socket /tmp/openshell-driver.sock \
       --db-url "sqlite:/tmp/openshell-gateway.db?mode=rwc" \
       --config /tmp/openshell-gateway.toml
   ```

   The gateway binds to the `lxdbr0` bridge address: the default loopback-only
   bind is unreachable from sandboxes, and the driver points each sandbox's
   `OPENSHELL_ENDPOINT` at that address. With a client CA the gateway requires
   a client certificate on every connection, from the CLI and from sandboxes
   alike.

   Run the supervisor released with the gateway: pass
   `--supervisor-image ghcr.io/nvidia/openshell/supervisor:<gateway version>`
   to the driver. A supervisor from a different release than the gateway can
   fail to sync policy and exit.

5. **Register the gateway with the CLI and create a sandbox.** The CLI
   imports the client certificate from `OPENSHELL_LOCAL_TLS_DIR`:

   ```sh
   OPENSHELL_LOCAL_TLS_DIR="$PKI" \
       openshell gateway add "https://$BRIDGE_IP:17670" --local --name lxd-demo
   openshell gateway select lxd-demo

   openshell sandbox create --name demo -- id
   openshell sandbox exec demo -- id
   openshell sandbox delete demo
   ```

## Security limitations

- **Every sandbox holds the same gateway client certificate.** As with
  upstream's Docker driver, the certificate and key passed with
  `--guest-tls-cert`/`--guest-tls-key` are copied into each sandbox (mode
  `0400`, owned by root, for the supervisor). The gateway identifies a
  sandbox by its sandbox token, not its certificate, and a gateway with
  mTLS authentication accepts that certificate as a client, so root inside a
  sandbox holds a credential the gateway trusts.
- **No default-deny egress or sandbox-to-sandbox network isolation.**
  Sandboxes can reach each other and the network freely today. `lxd-client`
  has the Network ACL APIs needed to build this, but nothing in the driver
  calls them yet.
- **`--sandbox-nesting` widens the container's trust boundary.** Sandboxes
  are unprivileged and unnested by default. Nesting, for workloads that run
  containers themselves, grants the `userns` capability, relaxes `/proc/sys`
  and cgroup mount restrictions, and allows AppArmor-stacking access —
  independent of `security.privileged`, which is never set.
- **PID limits are enforced, other cgroup limits are not.** Every sandbox
  gets `limits.processes` (`--default-max-processes`, default 4096) so one
  sandbox cannot fork-bomb its co-tenants, but there is no I/O or PID-cgroup
  budgeting beyond that, and CPU/memory are only set when the request asks
  for them.
- **No seccomp/AppArmor allowlist audit yet.** Sandboxes rely on LXD's
  default seccomp deny list (`kexec_load`, `open_by_handle_at`,
  `init_module`, `delete_module`), not a syscall allowlist scoped to what the
  supervisor actually needs.
- **`Ready=True` reflects LXD container status, not confirmed
  supervisor-to-gateway connectivity.** A sandbox can report `Ready=True` as
  soon as the LXD container reaches `Running`, before the supervisor inside
  has finished booting and connecting to the gateway. Correctly wiring this
  needs a guest-to-driver signal that containers don't provide; the fix lands
  with a planned microVM + `lxd-agent`-over-vsock transition, not before.

  As a partial mitigation, `create_sandbox` checks the instance again a few
  seconds after start and restarts it up to `--start-retries` times (default
  1) if its init has already exited. The container's init *is* the
  supervisor, so a supervisor that gives up during start-up — losing a race
  with the gateway finishing the sandbox record, say — otherwise leaves the
  instance `Stopped` with nothing to bring it back: LXD's `boot.autorestart`
  is VM-only and `boot.autostart` only covers daemon restarts.

## Networks and Storage Pools

Every sandbox gets a NIC on one LXD network and its root disk on one storage
pool. The operator sets where sandboxes go by default, so users creating
sandboxes need not know how the LXD behind the gateway is laid out:

- `--default-network` (default `lxdbr0`): the network sandboxes attach to.
  On MicroCloud this is usually the OVN network `default`.
- `--default-storage-pool` (default `default`): the pool for root disks. On
  MicroCloud this is usually `local` or `remote`.

A request can still choose per sandbox with `driver_config.network` and
`driver_config.storage_pool` (for example
`openshell sandbox create --driver-config-json '{"lxd":{"storage_pool":"remote"}}'`).
A create naming a network or pool that does not exist in the driver's
project fails straight away with `FailedPrecondition`, before any image is
imported.

### Reaching a remote LXD

With `--lxd-url https://<address>:8443` plus `--lxd-client-cert` and
`--lxd-client-key` the driver talks to LXD over the network instead of its
local socket. LXD's self-signed certificate names only the host's hostname
and loopback addresses, so a server reached by IP address fails ordinary
verification. Pass the certificate LXD presents with `--lxd-server-cert` to
trust exactly that certificate, as `lxc remote add` does; on a cluster member
such as a MicroCloud node that is `/var/snap/lxd/common/lxd/cluster.crt`.
`--lxd-server-ca` instead verifies against a CA, including the host name. Trust
the client certificate in LXD restricted to the driver's project:
`lxc config trust add client.crt --restricted --projects <project>`.

### Reaching the gateway

Each sandbox's supervisor connects back to the gateway at
`OPENSHELL_ENDPOINT`. By default the driver derives it from the host-side
address of the sandbox's network and `--gateway-grpc-port`, which suits a
gateway listening on an LXD bridge on the same machine. Anywhere else — a
gateway in an instance or on another machine, or sandboxes on an OVN network,
whose address belongs to its virtual router — set it explicitly with
`--gateway-endpoint` (for example `https://10.131.189.2:17670`). A sandbox on
an OVN network without `--gateway-endpoint` is refused with
`FailedPrecondition` rather than pointed at the router. When sandboxes reach
the gateway at an address its certificate does not name, `--gateway-tls-server-name`
sets the name they verify the certificate against instead.

## Images and Caching

The driver supports per-sandbox OCI images specified via `template.image` in the
gateway request (e.g. `docker://registry.example.com/org/sandbox:latest` or
`ghcr.io/org/custom-sandbox:v1`).

- **Contract:** `template.image` specifies the Linux rootfs OCI image for the sandbox.
  The driver automatically injects `/openshell-init.sh` and attaches the supervisor
  (extracted from `--supervisor-image`), so the image does not need to bundle the supervisor.
- **Digest-pinned resolution and caching:** On `create_sandbox`, the driver validates
  the OCI reference and resolves the manifest digest for the host architecture
  by reading the raw image index and selecting the matching `os`/`architecture`
  entry, so two architectures of the same tag never share a cache entry. It maps
  the digest to a local LXD image alias (e.g. `openshell-oci-r3-<64-hex-sha256>`, where `r3` is the conversion revision: a driver that converts images differently imports them again instead of reusing old conversions).
  If the alias is already present in LXD, it is reused immediately.
  If not cached, the driver pulls the image by digest using `skopeo`, unpacks it with
  `umoci`, packs it into squashfs and metadata archives, and imports it via LXD's
  split image REST API.
- **Init:** Conversion adds the driver's init script as `/openshell-init.sh`
  and points `/sbin/init` at it, replacing any init the image ships. LXD
  starts `/sbin/init` in a container, and the script sets up networking and
  hands over to the supervisor. The driver sets no `raw.*` keys and, unless
  `--sandbox-nesting` is given, no `security.nesting`, so sandboxes run in a
  restricted project with its default restrictions.
- **Tag mutation:** Because the cache is keyed on content digest rather than tag,
  if a tag points to a new digest, the driver will automatically pull and import the new
  image on first use.
- **Fallback:** If `template.image` is omitted or empty, the sandbox falls back to
  `--default-image` (default: the upstream community `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`),
  which is resolved and imported through the same on-demand path.
- **Configuration flags:**
  - `--supervisor-image`: OCI image reference to extract the OpenShell supervisor binary from (default: `ghcr.io/nvidia/openshell/supervisor:latest`).
  - `--supervisor-bin`: optional path to a pre-extracted supervisor binary on the host (bypasses extraction).
  - `--supervisor-cache-dir`: host directory for caching extracted supervisor binaries by content digest (default: `/var/cache/openshell/lxd-supervisor`).
  - `--supervisor-storage-pool`: LXD storage pool for the supervisor and DHCP-client volumes. When unset, each sandbox's own pool (`driver_config.storage_pool`, itself defaulting to `default`) is used, so the auxiliary volumes always land beside the rootfs they attach to. Set it to pin every auxiliary volume to one pool.
  - `--dhcp-client-bin`: optional path to a DHCP client binary on the host (defaults to searching PATH and standard locations for `udhcpc` or `busybox`).
  - `--image-work-dir`: host scratch directory for image conversion (default: `/var/cache/openshell/lxd-image-work`). Must not be a small tmpfs such as `/tmp`.
  - `--default-max-processes`: `limits.processes` applied to every sandbox, bounding its PID count (default: 4096; `0` leaves it unlimited). Overridable per sandbox via `driver_config.max_processes`.
  - `--start-retries`: how many times to restart a sandbox whose init exits immediately after the first start (default: 1; `0` disables).
  - `--image-pull-timeout-secs`: timeout for image inspection and pulling (default: 300s).
  - `--image-cache-alias-prefix`: prefix for cached LXD aliases (default: `openshell-oci-`).
  - `--skopeo-path`, `--umoci-path`, `--mksquashfs-path`: optional binary path overrides.

### Supervisor Binary Delivery via Custom Storage Volume

Upstream Docker and Podman drivers extract the supervisor binary (`/openshell-sandbox`) to a host cache and bind-mount it into sandboxes. For LXD, a host-path bind mount fails in clustered or distributed storage environments (e.g. Ceph) where containers may run on cluster nodes different from the driver host.

`openshell-driver-lxd` instead packages the supervisor binary into a digest-keyed LXD custom storage volume (`openshell-supervisor-<digest>`) on the sandbox's own storage pool (or `--supervisor-storage-pool` when pinned), following the pattern established in `canonical/workshop` (`lxd_backend_sdk.go`):
- **Volume layout & Mount distinction:** A `content-type: filesystem` storage volume is a filesystem tree. The volume contains `openshell-sandbox` at its root and is attached to each sandbox container as a read-only `disk` device mounted at directory `/opt/openshell/bin`. The injected guest init script (`/openshell-init.sh`) execs the binary at `/opt/openshell/bin/openshell-sandbox`.
- **Clustered LXD safety:** Because the disk device refers to a named storage-pool volume rather than a local host path, LXD manages replication and cluster-wide attachment automatically.
- **Idempotency & Race safety:** Volume creation is serialized in-process per pool and digest, and a creation that loses a race is reconciled by re-checking whether the volume now exists rather than by matching LXD's error wording. Subsequent sandboxes reusing the same supervisor binary digest share the volume.

### Fallback DHCP Client Delivery

Guest networking on LXD containers relies on DHCP over `eth0`. Some base sandbox images (such as `ghcr.io/nvidia/openshell-community/sandboxes/base:latest`) do not bundle any DHCP client.

To guarantee sandboxes obtain an IP lease regardless of what packages are installed in the guest image:
- The driver takes a static DHCP client (`udhcpc` or `busybox`) from the host environment (or `--dhcp-client-bin`) alongside the embedded event script (`udhcpc.script`).
- On sandbox creation, a digest-keyed custom storage volume (`openshell-dhcp-client-<digest>`) is provisioned on the storage pool and mounted read-only at `/opt/openshell/net`.
- In `/openshell-init.sh`, the init script probes for existing image-provided DHCP clients (`udhcpc`, `dhclient`, `dhcpcd`). If none are present on `PATH`, it runs the fallback client (`/opt/openshell/net/udhcpc`) with `/opt/openshell/net/udhcpc.script` in the background to acquire and apply the network lease.

## Sandbox State Reporting

The driver subscribes to LXD's lifecycle event stream and pushes an updated
sandbox snapshot to the gateway as soon as an instance changes state, rather
than leaving the gateway to notice on its next reconcile (up to a minute
later). A sandbox whose supervisor dies is reported in well under a second,
and a sandbox whose instance is deleted outside the driver (for example with
`lxc delete`) is reported as deleted. A watch that (re)connects first
receives the current state of every sandbox, so nothing that changed while
the driver or gateway was restarting is missed.

When a sandbox is not ready, the condition's `message` says why; for an
exited supervisor it names the `lxc console <name> --show-log` command that
shows the supervisor's output.

The `Ready` condition's `reason` uses the cross-driver vocabulary upstream
defines in `openshell-core::driver_utils`, because the gateway keys real
behaviour off these exact strings — which reasons are transient (mapping to
`Provisioning` rather than `Error`) and which are eligible for recovery when
the gateway restarts:

| LXD state | reason | gateway phase |
| --- | --- | --- |
| `Running` / `Ready` | — (`Ready=True`) | `Ready` |
| `Stopped`, init exited by itself | `ContainerExited` | `Error` (terminal) |
| `Stopped`, stop requested | `ContainerStopped` | `Stopped` |
| `Stopped`, never started | `ContainerCreated` | `Provisioning` |
| `Starting` | `ContainerStarting` | `Provisioning` |
| `Frozen` | `ContainerPaused` | `Error` |

LXD reports the same `Stopped` status however an instance went down, so the
driver records `user.openshell.stop_intent` on the instance when it is asked
to stop one. Without it a user-requested stop is indistinguishable from a
crash and surfaces as `Error` instead of `Stopped`. Starting the sandbox again
(`openshell sandbox start`) clears the marker and pushes the current TLS
materials before the instance starts.

Note that the supervisor does not act on LXD's shutdown signal, so a graceful
stop never completes on its own. `stop_sandbox` bounds the graceful attempt
with `--stop-timeout-secs` (default 10s) and then stops the instance forcibly.

## Conformance

`make test-conformance` runs upstream OpenShell's own conformance suite
(`openshell-conformance`) against a gateway backed by this driver on the
local LXD, the way upstream validates its in-tree drivers:

- `smoke`: create a sandbox, see it `Ready`, list it, exec in it, delete it.
- `sandbox-continuity`: a running sandbox keeps its workload and a stopped
  one stays stopped across a gateway restart and a driver restart.

Both this and `make test-upstream-e2e` below run in the environment
`scripts/openshell-env.sh` provides. It pins the OpenShell side to one
release — gateway, CLI and supervisor image from v0.0.116, verified by
checksum and digest — because mixing components from different releases
fails in ways that are not the driver's, and runs everything in a throwaway
LXD project (`openshell-test`) that shares the default project's image cache.
The conformance runner is built from the newest upstream revision the pinned
CLI can drive.

On failure, the driver and gateway logs and LXD's lifecycle events are left
in `target/openshell-test/artifacts`, with each suite's reports in a
subdirectory. `scripts/openshell-env.sh up` starts the environment and
leaves it running for debugging; `scripts/openshell-env.sh down` removes it.

`make test-upstream-e2e` runs, against the same environment and release,
upstream's end-to-end tests for what happens inside a sandbox: L4 and L7
network policy, SSRF protections, credential handling, live policy updates,
Landlock filesystem rules and `inference.local` routing. The supervisor
enforces all of this, but only as far as the container lets it, and a sandbox
that silently enforces nothing still passes smoke. The tests come from the
v0.0.116 source tree (the Rust tests of `e2e/rust` and the Python tests of
`e2e/python`, run through the release's Python SDK); upstream tests specific
to the Docker or Podman drivers are left out. It additionally needs rootless
podman (with `uidmap` and `passt`) for a test fixture server, and
`python3` 3.11 or newer. Logs and a JUnit report land in
`target/openshell-test/artifacts/upstream-e2e`.

## Known limitations

- GPU requests attach every host GPU; an exact requested `count` isn't honored.
- `lxd-client` opens a fresh connection per request; no connection pooling.
- No MicroCloud / multi-node cluster scheduling — single LXD daemon only.
- Not yet packaged as a snap for production distribution (see [Snap](#snap)
  for the local build path that exists today).

## Snap

The repository ships a snap package definition in `snap/snapcraft.yaml`.

### Build the snap locally

```sh
snapcraft
```

Snapcraft uses LXD as its build environment — install and initialise it first
if needed:

```sh
sudo snap install lxd
lxd init --auto
sudo snap install snapcraft --classic
```

### Install and run

```sh
sudo snap install openshell-driver-lxd_*.snap --dangerous
sudo snap connect openshell-driver-lxd:lxd lxd
sudo openshell-driver-lxd
```

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE).

## Development

See [AGENTS.md](AGENTS.md) for development and contribution conventions.
