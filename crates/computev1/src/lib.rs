// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generated tonic + prost code for the OpenShell ComputeDriver service.
//!
//! The proto schema is vendored from NVIDIA/OpenShell under `proto/`
//! (Apache-2.0). All types below are emitted by `tonic-prost-build` at compile
//! time and never committed to source control.
//!
//! `compute_driver.proto` imports three more packages: `extension.proto` for
//! the protocol metadata the gateway negotiates with, `sandbox.proto` for the
//! effective policy handed to the driver, and `datamodel.proto`, which
//! `sandbox.proto` imports. The module tree below mirrors the proto package
//! names, because that is what the generated code's own `super::super::` paths
//! resolve against; `pb` keeps the driver's existing path to the compute
//! package.

#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]

pub mod openshell {
    pub mod compute {
        pub mod v1 {
            tonic::include_proto!("openshell.compute.v1");
        }
    }

    pub mod extension {
        pub mod v1 {
            tonic::include_proto!("openshell.extension.v1");
        }
    }

    pub mod sandbox {
        pub mod v1 {
            tonic::include_proto!("openshell.sandbox.v1");
        }
    }

    pub mod datamodel {
        pub mod v1 {
            tonic::include_proto!("openshell.datamodel.v1");
        }
    }
}

pub use openshell::compute::v1 as pb;
pub use openshell::datamodel::v1 as datamodelv1;
pub use openshell::extension::v1 as extensionv1;
pub use openshell::sandbox::v1 as sandboxv1;

pub use pb::compute_driver_client;
pub use pb::compute_driver_server;
