// SPDX-License-Identifier: AGPL-3.0-or-later

//! WatchSandboxes: state changes the driver pushes to the gateway as they
//! happen, instead of leaving them to the gateway's 60-second reconcile.
//!
//! Every assertion waits for a pushed event within [`PUSH_TIMEOUT`]; polling
//! GetSandbox would pass even if nothing were pushed.

use std::time::Duration;

use crate::harness::*;

#[tokio::test]
async fn requested_stop_is_pushed_as_container_stopped() {
    let driver = Driver::start().await;
    let name = unique_name("wstop");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    let mut watch = driver.watch().await;

    driver.create_running(&name).await;
    watch.expect_snapshot(&id, "True", "").await;

    driver
        .stop(&name)
        .await
        .expect("stop_sandbox should succeed");
    watch
        .expect_snapshot(&id, "False", "ContainerStopped")
        .await;
}

/// A stopped sandbox starts again and reads as ready; the stop is forgotten,
/// so a supervisor that exits afterwards reads as exited, not as stopped on
/// request.
#[tokio::test]
async fn started_sandbox_is_ready_and_forgets_the_stop() {
    let driver = Driver::start().await;
    let name = unique_name("wstart");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    let mut watch = driver.watch().await;

    driver.create_running(&name).await;
    watch.expect_snapshot(&id, "True", "").await;
    // Starting a running sandbox changes nothing.
    driver
        .start_sandbox(&name)
        .await
        .expect("start_sandbox on a running sandbox should succeed");

    driver
        .stop(&name)
        .await
        .expect("stop_sandbox should succeed");
    watch
        .expect_snapshot(&id, "False", "ContainerStopped")
        .await;

    driver
        .start_sandbox(&name)
        .await
        .expect("start_sandbox should succeed");
    watch.expect_snapshot(&id, "True", "").await;

    driver.exit_supervisor(&name, 0).await;
    watch.expect_snapshot(&id, "False", "ContainerExited").await;
}

/// Starting a paused sandbox cannot make it run, so it is refused rather
/// than reported as started.
#[tokio::test]
async fn starting_a_paused_sandbox_is_refused() {
    let driver = Driver::start().await;
    let name = unique_name("wpaused");
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    lxc(&["pause", &name]);

    let status = driver
        .start_sandbox(&name)
        .await
        .expect_err("a paused sandbox cannot be started");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition, "{status}");
    assert!(status.message().contains("Frozen"), "{status}");

    lxc(&["start", &name]);
}

/// The supervisor exiting by itself is the case the watcher exists for: LXD
/// reports `instance-shutdown` and the sandbox must read as exited, not
/// stopped.
#[tokio::test]
async fn supervisor_exit_is_pushed_as_container_exited() {
    let driver = Driver::start().await;
    let name = unique_name("wexit");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    let mut watch = driver.watch().await;

    driver.exit_supervisor(&name, 0).await;

    let sandbox = watch.expect_snapshot(&id, "False", "ContainerExited").await;
    assert_eq!(sandbox.name, name);
}

/// A sandbox LXD stopped — with the daemon or the host — and did not bring
/// back keeps `volatile.last_state.power=RUNNING`; that marker is the only
/// thing separating it from an init that exited.
///
/// The driver no longer trusts the marker on sight, because LXD leaves it at
/// `RUNNING` for about 0.7s after an init that exits moments after starting
/// (LXD 6.9). It confirms it by re-reading, and a marker that survives still
/// has to report the runtime restart.
#[tokio::test]
async fn a_sandbox_lxd_stopped_is_reported_as_a_runtime_restart() {
    let driver = Driver::start().await;
    let name = unique_name("wrestart");
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    // Down, with no stop the driver was asked for, and still recorded as
    // having been running: what LXD leaves behind when it goes down under a
    // sandbox and does not autostart it again.
    lxc(&["stop", "--force", &name]);
    lxc(&[
        "config",
        "set",
        &name,
        "volatile.last_state.power",
        "RUNNING",
    ]);

    let cond = driver.ready_condition(&name).await;
    assert_eq!(cond.reason, "ContainerRuntimeRestart", "{cond:?}");
    assert_eq!(cond.status, "False", "{cond:?}");
}

#[tokio::test]
async fn out_of_band_force_stop_is_pushed_as_container_exited() {
    let driver = Driver::start().await;
    let name = unique_name("wforce");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    let mut watch = driver.watch().await;

    lxc(&["stop", "--force", &name]);

    watch.expect_snapshot(&id, "False", "ContainerExited").await;
}

#[tokio::test]
async fn freeze_and_resume_are_pushed() {
    let driver = Driver::start().await;
    let name = unique_name("wfreeze");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    let mut watch = driver.watch().await;

    lxc(&["pause", &name]);
    watch.expect_snapshot(&id, "False", "ContainerPaused").await;

    // `lxc start` on a frozen instance resumes it.
    lxc(&["start", &name]);
    watch.expect_snapshot(&id, "True", "").await;
}

/// A sandbox the driver restarted out of band comes back as running.
#[tokio::test]
async fn out_of_band_start_is_pushed_as_running() {
    let driver = Driver::start().await;
    let name = unique_name("wstart");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    driver
        .stop(&name)
        .await
        .expect("stop_sandbox should succeed");
    let mut watch = driver.watch().await;

    lxc(&["start", &name]);
    lxc(&["start", &format!("{name}-supervisor")]);

    watch.expect_snapshot(&id, "True", "").await;
}

#[tokio::test]
async fn delete_rpc_pushes_deleted_with_the_sandbox_id() {
    let driver = Driver::start().await;
    let name = unique_name("wdel");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    let mut watch = driver.watch().await;

    assert!(driver
        .delete(&name)
        .await
        .expect("delete_sandbox should succeed"));

    watch.expect_deleted(&id).await;
}

/// Every connected watcher gets every event: the gateway may hold more than
/// one stream across a reconnect.
#[tokio::test]
async fn every_watcher_receives_pushed_events() {
    let driver = Driver::start().await;
    let name = unique_name("wfan");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    let mut first = driver.watch().await;
    let mut second = driver.watch().await;

    driver.exit_supervisor(&name, 0).await;

    first.expect_snapshot(&id, "False", "ContainerExited").await;
    second
        .expect_snapshot(&id, "False", "ContainerExited")
        .await;
}

/// The LXD event stream carries every instance on the host; only
/// driver-managed ones may be reported.
#[tokio::test]
async fn unmanaged_instances_are_not_pushed() {
    let driver = Driver::start().await;
    let unmanaged = unique_name("wunmgd");
    let managed = unique_name("wmgd");
    let _cleanup = driver.cleanup(&[&unmanaged, &managed]);
    let alias = ensure_sandbox_image();
    let mut watch = driver.watch().await;

    // Starting it produces lifecycle events; its init has no supervisor to
    // exec and exits, producing more.
    lxc(&["init", &alias, &unmanaged]);
    let _ = lxc_output(&["start", &unmanaged]);
    watch
        .expect_silence_about(&unmanaged, "", Duration::from_secs(5))
        .await;

    // The stream is still delivering: a managed sandbox shows up.
    driver.create_running(&managed).await;
    watch
        .expect_snapshot(&sandbox_id(&managed), "True", "")
        .await;
}

/// Removing a sandbox's instance behind the driver's back reaches the
/// gateway as a deletion, instead of waiting for its orphan sweep.
#[tokio::test]
async fn out_of_band_delete_is_pushed_as_deleted() {
    let driver = Driver::start().await;
    let name = unique_name("woobdel");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    let mut watch = driver.watch().await;

    lxc(&["delete", "--force", &name]);

    watch.expect_deleted(&id).await;
}

/// A sandbox created after the watcher subscribed is known to it too.
#[tokio::test]
async fn out_of_band_delete_of_a_sandbox_created_after_subscribing_is_pushed() {
    let driver = Driver::start().await;
    let mut watch = driver.watch().await;
    let name = unique_name("wlate");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;
    watch.expect_snapshot(&id, "True", "").await;

    lxc(&["delete", "--force", &name]);

    watch.expect_deleted(&id).await;
}

/// Deleting an unmanaged instance says nothing.
#[tokio::test]
async fn out_of_band_delete_of_an_unmanaged_instance_is_not_pushed() {
    let driver = Driver::start().await;
    let name = unique_name("wunmdel");
    let _cleanup = driver.cleanup(&[&name]);
    let alias = ensure_sandbox_image();
    lxc(&["init", &alias, &name]);
    let mut watch = driver.watch().await;

    lxc(&["delete", "--force", &name]);

    watch
        .expect_silence_about(&name, "", Duration::from_secs(5))
        .await;
}

/// A new watcher learns the current state of every sandbox, or anything that
/// changed while it was disconnected would wait for the next reconcile.
#[tokio::test]
async fn new_watcher_receives_current_state() {
    let driver = Driver::start().await;
    let name = unique_name("wsnap");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    let mut watch = driver.watch().await;

    watch.expect_snapshot(&id, "True", "").await;
}

/// The same, as the gateway meets it: the driver restarts (upgrade, crash),
/// a sandbox dies meanwhile, and the reconnecting gateway is told at once.
/// Before the subscribe snapshot, it took the gateway 54s to notice.
#[tokio::test]
async fn restarted_driver_reports_changes_made_while_down() {
    let driver = Driver::start().await;
    let name = unique_name("wdown");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    driver.kill();
    lxc(&["stop", "--force", &name]);
    driver.restart().await;

    let mut watch = driver.watch().await;
    watch.expect_snapshot(&id, "False", "ContainerExited").await;
}
