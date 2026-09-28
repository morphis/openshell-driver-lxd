// SPDX-License-Identifier: AGPL-3.0-or-later

//! The driver process itself: its socket, restarts, and startup.

use std::time::{Duration, Instant};

use computev1::pb::GetCapabilitiesRequest;
use tokio::net::TcpListener;
use tonic::Request;

use crate::harness::*;

#[tokio::test]
async fn capabilities_are_served_over_the_socket() {
    let driver = Driver::start().await;

    let response = driver
        .client()
        .await
        .get_capabilities(Request::new(GetCapabilitiesRequest {
            gateway: Some(openshell_driver_lxd::protocol::gateway_metadata()),
        }))
        .await
        .expect("get_capabilities")
        .into_inner();

    assert_eq!(response.driver_name, "lxd");
    assert_eq!(response.default_image, SANDBOX_IMAGE);

    let mode = std::fs::metadata(driver.socket())
        .map(|m| std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777)
        .expect("socket exists");
    assert_eq!(mode, 0o600, "only the gateway's user may connect");
}

/// A crashed driver leaves its socket file behind; the next start must
/// replace it rather than fail to bind.
#[tokio::test]
async fn restart_replaces_a_stale_socket() {
    let driver = Driver::start().await;
    driver.kill();
    assert!(
        driver.socket().exists(),
        "a killed driver leaves its socket"
    );

    driver.restart().await;
}

#[tokio::test]
async fn refuses_to_replace_a_path_that_is_not_a_socket() {
    let driver = Driver::spawn(DriverOptions::default());
    driver.kill();
    std::fs::write(driver.socket(), b"not a socket").unwrap();

    driver.restart_without_waiting();
    let status = driver
        .wait_exit(Duration::from_secs(30))
        .await
        .expect("driver should refuse to start");
    assert!(!status.success());
    assert_eq!(std::fs::read(driver.socket()).unwrap(), b"not a socket");
}

/// Sandboxes survive a driver restart, and the new process manages them.
#[tokio::test]
async fn sandboxes_survive_a_driver_restart() {
    let driver = Driver::start().await;
    let name = unique_name("survive");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    driver.restart().await;

    assert_eq!(driver.ready_condition(&name).await.status, "True");
    let mut watch = driver.watch().await;
    driver.exit_supervisor(&name, 0).await;
    watch.expect_snapshot(&id, "False", "ContainerExited").await;
}

/// Pre-warming the default image does not delay serving: the socket accepts
/// connections as soon as it is bound, so a gateway that connected during a
/// slow pre-warm would otherwise wait without any error until it finished.
#[tokio::test]
async fn serves_while_the_default_image_prewarms() {
    // A registry that accepts connections and never answers.
    let registry = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = registry.local_addr().unwrap();
    let hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((conn, _)) = registry.accept().await {
            held.push(conn);
        }
    });

    let driver = Driver::spawn(DriverOptions {
        default_image: format!("{address}/openshell/slow:latest"),
        ..Default::default()
    });
    let started = Instant::now();
    driver.wait_ready(Duration::from_secs(60)).await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(5), "serving took {elapsed:?}");
    assert!(
        !driver.log().contains("pre-warm"),
        "the pre-warm should still be in progress while serving"
    );

    // The pre-warm still runs, and reports its failure once the registry
    // goes away.
    hold.abort();
    eventually(
        Duration::from_secs(60),
        "the pre-warm to give up",
        || async {
            driver
                .log()
                .contains("could not pre-warm default sandbox image")
                .then_some(())
        },
    )
    .await;
}

#[tokio::test]
async fn default_image_is_prewarmed_in_the_background() {
    let driver = Driver::start().await;

    eventually(
        Duration::from_secs(60),
        "the pre-warm to finish",
        || async {
            driver
                .log()
                .contains("default sandbox image ready")
                .then_some(())
        },
    )
    .await;
}
