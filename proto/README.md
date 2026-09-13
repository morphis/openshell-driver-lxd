# proto/

`compute_driver.proto` is vendored from
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) (Apache-2.0) — it
defines the `openshell.compute.v1.ComputeDriver` gRPC service that out-of-tree
compute drivers implement.

`crates/computev1` generates tonic/prost bindings from this file at build
time via `tonic-prost-build`.

It is vendored at the newest OpenShell release the driver targets, currently
`v0.1.0-pre.1`. Its changes over `v0.0.116` are additive, so the driver serves
both releases' gateways.

To update: `make sync-proto OPENSHELL_REF=<tag>` copies `compute_driver.proto`
and `options.proto` from that upstream tag and builds the workspace to
confirm they still compile; bump the release pinned in
`scripts/openshell-env.sh` in the same change. Preserve the original `SPDX-FileCopyrightText` /
`SPDX-License-Identifier: Apache-2.0` header. See `THIRD-PARTY-NOTICES` for
attribution details.
