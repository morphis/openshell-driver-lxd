# openshell-driver-lxd

[OpenShell](https://github.com/NVIDIA/OpenShell) Compute driver for LXD / MicroCloud.

The driver utilizes system containers provided by LXD to host sandboxes managed by
OpenShell and provides the necessary integration between both sides.

## Overview

`openshell-driver-lxd` is an out-of-tree [OpenShell](https://github.com/NVIDIA/OpenShell)
compute driver. It implements OpenShell's `compute_driver.proto` contract and serves it
over gRPC via a Unix domain socket, which the OpenShell gateway connects to at startup.

A sandbox is two containers. From OpenShell v0.1.0 the supervisor is split
into an out-of-workload companion, which holds the gateway credentials, and an
in-workload boundary, which runs beside the user's own image — see
[docs/architecture.md](docs/architecture.md).

Three OCI images are published in lock step, all built from one pinned
upstream revision:

| image | contents |
|---|---|
| `ghcr.io/canonical/openshell-gateway` | the OpenShell gateway and this driver |
| `ghcr.io/canonical/openshell-supervisor` | the out-of-workload half of a sandbox |
| `ghcr.io/canonical/openshell-sandbox` | the in-workload boundary |

## Requirements

Sandboxes need an **OVN network**. Their egress ACL is the outer network fence
OpenShell v0.1.0 requires before a workload runs, and LXD applies a per-NIC ACL
only on OVN; the driver refuses to create a sandbox it cannot fence.

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE).

Also see [THIRD-PARTY-NOTICES](./THIRD-PARTY-NOTICES).
