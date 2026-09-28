# proto/

These files are vendored from
[NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) (Apache-2.0).
`compute_driver.proto` defines the `openshell.compute.v1.ComputeDriver` gRPC
service that out-of-tree compute drivers implement; the others are the files it
imports, directly or not:

| file | why it is here |
|---|---|
| `compute_driver.proto` | the driver contract |
| `options.proto` | the custom field and method options it uses, such as `secret` |
| `extension.proto` | `PeerMetadata`, the protocol metadata the gateway negotiates with |
| `sandbox.proto` | `SandboxPolicy`, the effective policy handed to the driver |
| `datamodel.proto` | imported by `sandbox.proto` |

`crates/computev1` generates tonic/prost bindings from them at build time via
`tonic-prost-build`.

They are vendored at the newest OpenShell release the driver targets, currently
`v0.1.0-pre.11`. Unlike earlier bumps this one is **not** backwards compatible:
`GetGatewayListenerRequirements` is gone, `sandbox_name` is `name`, condition
and event timestamps are `google.protobuf.Timestamp`, and a gateway now refuses
a driver that does not return `extension` metadata or whose
`resource_admission_policy` differs from its own. A v0.0.116 gateway cannot
drive this build, and this build cannot drive a v0.0.116 gateway.

To update: `make sync-proto OPENSHELL_REF=<tag>` copies the files above from
that upstream tag and builds the workspace to confirm they still compile; bump
the release pinned in `scripts/openshell-env.sh` in the same change. Preserve
the original `SPDX-FileCopyrightText` / `SPDX-License-Identifier: Apache-2.0`
headers. See `THIRD-PARTY-NOTICES` for attribution details.
