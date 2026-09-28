// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

use clap::Parser;
use computev1::pb::compute_driver_server::ComputeDriver;
use computev1::pb::GetCapabilitiesRequest;
use lxd_client::{LxdClient, LxdEndpoint};
use openshell_driver_lxd::config::{Config, DEFAULT_LXD_SOCKET};
use openshell_driver_lxd::driver::LxdComputeDriver;
use openshell_driver_lxd::grpc::ComputeDriverService;
use tonic::Request;

#[tokio::test]
async fn get_capabilities_returns_driver_info() {
    let config = Config::parse_from(["openshell-driver-lxd"]);
    let lxd = LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();
    // No watcher: this test only reads static capabilities and must not
    // depend on a reachable LXD event stream.
    let service = ComputeDriverService::without_watcher(LxdComputeDriver::new(config, lxd));

    let response = service
        .get_capabilities(Request::new(GetCapabilitiesRequest {
            gateway: Some(openshell_driver_lxd::protocol::gateway_metadata()),
        }))
        .await
        .expect("get_capabilities should succeed")
        .into_inner();

    assert_eq!(response.driver_name, "lxd");
    assert_eq!(response.driver_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        response.default_image,
        "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
    );
}
