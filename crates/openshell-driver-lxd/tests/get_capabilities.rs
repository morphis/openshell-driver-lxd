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
    assert_eq!(response.default_image, "nvcr.io/nvidia/base/ubuntu:24.04");
    assert!(!response.driver_reports_runtime_readiness);
    assert!(response.resource_capabilities.is_some());
    assert_eq!(response.rootfs_tar_staging_dir, "");
    assert_eq!(response.rootfs_tar_max_bytes, 0);

    // Without these two a v0.1.0 gateway refuses the driver outright: no
    // protocol metadata means it will not activate it at all, and an
    // admission policy it does not recognize fails every create and start.
    let extension = response.extension.expect("protocol metadata is reported");
    assert_eq!(extension.protocol_version.expect("version").major, 1);
    assert!(extension
        .supported_capabilities
        .contains(&"openshell.compute.contract".to_string()));
    assert!(response
        .resource_admission_policy
        .starts_with("v1:{\"allow_driver_config\":false"));
}
