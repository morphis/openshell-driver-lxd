# proto/

`compute_driver.proto` is vendored from
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) (Apache-2.0) — it
defines the `openshell.compute.v1.ComputeDriver` gRPC service that out-of-tree
compute drivers implement.

`crates/computev1` generates tonic/prost bindings from this file at build
time via `tonic-prost-build`.

It is vendored at the OpenShell release the driver targets, currently
`v0.0.116`, the same release the upstream test suites run against (pinned in
`scripts/openshell-env.sh`), so the driver implements exactly the contract of
the gateway it is tested with.

To update: `make sync-proto OPENSHELL_REF=<tag>` copies `compute_driver.proto`
and `options.proto` from that upstream tag and builds the workspace to
confirm they still compile; bump the release pinned in
`scripts/openshell-env.sh` in the same change. Preserve the original `SPDX-FileCopyrightText` /
`SPDX-License-Identifier: Apache-2.0` header. See `THIRD-PARTY-NOTICES` for
attribution details.
