// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-contained async HTTP client for the LXD REST API, supporting both a
//! local Unix domain socket and a remote HTTPS+mTLS endpoint.

mod acls;
mod client;
mod error;
mod events;
mod images;
mod instances;
mod networks;
mod operations;
mod projects;
pub mod resources;
pub(crate) mod split_image_body;
pub mod storage;
mod types;

pub use acls::{AclAction, AclProtocol, AclState, LxdNetworkAclRule};
pub use client::{LxdClient, LxdEndpoint, LxdHttpsConfig, DEFAULT_PROJECT};
pub use error::LxdError;
pub use events::EventStream;
pub use types::{
    Image, ImageAlias, Instance, InstanceState, InstanceStateCpu, InstanceStateDisk,
    InstanceStateMemory, InstanceStateNetwork, InstanceStateNetworkAddress, LxdEvent,
    LxdServerInfo, Network, Operation, StorageVolume,
};
