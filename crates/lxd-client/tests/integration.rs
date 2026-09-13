// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration tests against a real LXD daemon: instance lifecycle,
//! operation waiting (including its headers-then-delayed-body timing),
//! and real error shapes.
//!
//! Requires a running LXD with a `default` storage pool, an `lxdbr0`
//! network, and a locally-published `lxd-client-test` image alias.
//! `make test` provisions all three before running (see
//! `scripts/setup-lxd-test-env.sh`); CI runs the same target.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lxd_client::{LxdClient, LxdEndpoint, LxdError, LxdNetworkAclRule, DEFAULT_PROJECT};

const TEST_IMAGE_ALIAS: &str = "lxd-client-test";
const LXD_SOCKET: &str = "/var/snap/lxd/common/lxd/unix.socket";

static NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

fn client() -> LxdClient {
    LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(LXD_SOCKET))).unwrap()
}

/// Short, unique-enough LXD instance name for one test run.
fn unique_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos();
    let n = NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("lxdc-{nanos:x}-{n}")
}

fn sandbox_devices() -> HashMap<String, HashMap<String, String>> {
    let mut devices = HashMap::new();

    let mut root = HashMap::new();
    root.insert("type".to_string(), "disk".to_string());
    root.insert("pool".to_string(), "default".to_string());
    root.insert("path".to_string(), "/".to_string());
    devices.insert("root".to_string(), root);

    let mut eth0 = HashMap::new();
    eth0.insert("type".to_string(), "nic".to_string());
    eth0.insert("network".to_string(), "lxdbr0".to_string());
    devices.insert("eth0".to_string(), eth0);

    devices
}

#[tokio::test]
async fn create_get_list_start_stop_delete_lifecycle() {
    let client = client();
    let name = unique_name();

    let mut config = HashMap::new();
    config.insert(
        "user.openshell.sandbox_id".to_string(),
        "test-sandbox".to_string(),
    );

    // Created stopped, so start_instance (not just create's own `start`
    // flag) gets exercised below.
    let create_op = client
        .create_instance(
            &name,
            TEST_IMAGE_ALIAS,
            config,
            sandbox_devices(),
            vec![],
            false,
        )
        .await
        .expect("create_instance should succeed");
    tokio::time::timeout(
        Duration::from_secs(60),
        client.wait_operation(&create_op.id),
    )
    .await
    .expect("create operation should not time out")
    .expect("create operation should complete successfully");

    let instance = client
        .get_instance(&name)
        .await
        .expect("get_instance should succeed");
    assert_eq!(instance.name, name);
    assert_eq!(instance.status, "Stopped");
    assert_eq!(
        instance
            .config
            .get("user.openshell.sandbox_id")
            .map(String::as_str),
        Some("test-sandbox")
    );

    let names: Vec<String> = client
        .list_instances()
        .await
        .expect("list_instances should succeed")
        .into_iter()
        .map(|instance| instance.name)
        .collect();
    assert!(names.contains(&name), "expected {name} in {names:?}");

    let start_op = client
        .start_instance(&name)
        .await
        .expect("start_instance should succeed");
    tokio::time::timeout(Duration::from_secs(60), client.wait_operation(&start_op.id))
        .await
        .expect("start operation should not time out")
        .expect("start operation should complete successfully");

    let running = client
        .get_instance(&name)
        .await
        .expect("get_instance should succeed after start");
    assert_eq!(running.status, "Running");

    let state = client
        .get_instance_state(&name)
        .await
        .expect("get_instance_state should succeed");
    assert_eq!(state.status, "Running");

    let stop_op = client
        .stop_instance(&name, true)
        .await
        .expect("stop_instance should succeed");
    tokio::time::timeout(Duration::from_secs(30), client.wait_operation(&stop_op.id))
        .await
        .expect("stop operation should not time out")
        .expect("stop operation should complete successfully");

    let stopped = client
        .get_instance(&name)
        .await
        .expect("get_instance should succeed after stop");
    assert_eq!(stopped.status, "Stopped");

    let delete_op = client
        .delete_instance(&name)
        .await
        .expect("delete_instance should succeed");
    tokio::time::timeout(
        Duration::from_secs(30),
        client.wait_operation(&delete_op.id),
    )
    .await
    .expect("delete operation should not time out")
    .expect("delete operation should complete successfully");

    let err = client
        .get_instance(&name)
        .await
        .expect_err("instance should be gone after delete");
    match err {
        LxdError::Api { status_code, .. } => assert_eq!(status_code, 404),
        other => panic!("expected LxdError::Api(404), got {other:?}"),
    }
}

#[tokio::test]
async fn create_instance_with_unknown_image_alias_fails() {
    let client = client();
    let name = unique_name();

    let create_op = client
        .create_instance(
            &name,
            "definitely-not-a-real-alias",
            HashMap::new(),
            HashMap::new(),
            vec![],
            false,
        )
        .await
        .expect("create_instance call itself should succeed (LXD accepts the request and returns an operation)");

    let err = tokio::time::timeout(
        Duration::from_secs(15),
        client.wait_operation(&create_op.id),
    )
    .await
    .expect("wait_operation should not time out")
    .expect_err("waiting on the operation should fail: the image alias doesn't exist");

    match err {
        LxdError::OperationFailed { .. } => {}
        other => panic!("expected LxdError::OperationFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn get_instance_unknown_name_returns_404() {
    let client = client();

    let err = client
        .get_instance("lxdc-definitely-does-not-exist")
        .await
        .expect_err("get_instance should fail for an unknown name");

    match err {
        LxdError::Api { status_code, .. } => assert_eq!(status_code, 404),
        other => panic!("expected LxdError::Api(404), got {other:?}"),
    }
}

#[tokio::test]
async fn wait_operation_unknown_id_returns_404() {
    let client = client();

    let err = tokio::time::timeout(
        Duration::from_secs(5),
        client.wait_operation("00000000-0000-0000-0000-000000000000"),
    )
    .await
    .expect("wait_operation should not hang on a 404")
    .expect_err("wait_operation should fail for an unknown id");

    match err {
        LxdError::Api { status_code, .. } => assert_eq!(status_code, 404),
        other => panic!("expected LxdError::Api(404), got {other:?}"),
    }
}

/// Held by tests that create or delete projects and by tests that update
/// network ACLs. Updating an ACL makes LXD look up every project that might
/// use it, and a project deleted during that lookup fails the update with
/// "Failed loading project ...: Project not found".
static PROJECT_SET_CHANGES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn ensure_network_acl_create_update_delete() {
    let _projects = PROJECT_SET_CHANGES.lock().await;
    let client = client();
    let acl_name = unique_name();

    client
        .ensure_network_acl(
            &acl_name,
            vec![LxdNetworkAclRule::allow_egress_tcp("10.0.0.0/8", 8080)],
        )
        .await
        .expect("ensure_network_acl should create a new ACL");

    // Idempotent: update the ruleset on an existing ACL.
    let rules = vec![
        LxdNetworkAclRule::allow_egress_tcp("192.168.0.0/16", 443),
        LxdNetworkAclRule::allow_egress("192.0.2.0/24,198.51.100.0/24", None, "")
            .described("any protocol"),
    ];
    client
        .ensure_network_acl(&acl_name, rules.clone())
        .await
        .expect("ensure_network_acl should update an existing ACL");

    // Unchanged rules leave the ACL alone: LXD reports no update. A driver
    // ensures its ACL on every sandbox create, so rewriting it each time
    // would churn the rules applied to every running sandbox.
    let mut events = client
        .subscribe_events(&["lifecycle"])
        .await
        .expect("subscribe to lifecycle events");
    client
        .ensure_network_acl(&acl_name, rules)
        .await
        .expect("ensure_network_acl with the same rules should succeed");
    assert!(
        !acl_updated(&mut events, &acl_name, Duration::from_secs(2)).await,
        "an unchanged ACL should not be rewritten"
    );
    // A real change is written, which also shows the check above can fail.
    client
        .ensure_network_acl(
            &acl_name,
            vec![LxdNetworkAclRule::allow_egress_tcp("192.168.0.0/16", 8443)],
        )
        .await
        .expect("ensure_network_acl should update changed rules");
    assert!(
        acl_updated(&mut events, &acl_name, Duration::from_secs(10)).await,
        "a changed ACL should be rewritten"
    );

    client
        .delete_network_acl(&acl_name)
        .await
        .expect("delete_network_acl should succeed");
}

/// Whether LXD reports ACL `name` updated within `wait`.
async fn acl_updated(events: &mut lxd_client::EventStream, name: &str, wait: Duration) -> bool {
    use futures::StreamExt;
    tokio::time::timeout(wait, async {
        while let Some(Ok(event)) = events.next().await {
            let action = event.metadata["action"].as_str().unwrap_or_default();
            let source = event.metadata["source"].as_str().unwrap_or_default();
            if action == "network-acl-updated"
                && source.split('?').next() == Some(&format!("/1.0/network-acls/{name}"))
            {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

#[tokio::test]
async fn delete_network_acl_nonexistent_is_ok() {
    let client = client();

    client
        .delete_network_acl("lxdc-definitely-does-not-exist-acl")
        .await
        .expect("delete_network_acl on a nonexistent ACL should return Ok");
}

#[tokio::test]
async fn project_exists_true_for_default_project() {
    let client = client();
    assert!(
        client
            .project_exists("default")
            .await
            .expect("project_exists should succeed"),
        "default project should exist"
    );
}

#[tokio::test]
async fn project_exists_false_for_nonexistent_project() {
    let client = client();
    let name = unique_name();
    assert!(
        !client
            .project_exists(&format!("{name}-missing"))
            .await
            .expect("project_exists should succeed"),
        "random project name should not exist"
    );
}

#[tokio::test]
async fn project_exists_with_non_default_project_client() {
    let _projects = PROJECT_SET_CHANGES.lock().await;
    let default_client = client();
    let project_name = unique_name();

    default_client
        .create_project(&project_name)
        .await
        .expect("create_project should succeed");

    let project_client = client().with_project(&project_name);

    // Verify project existence checks from the non-default project client.
    assert!(
        project_client
            .project_exists(&project_name)
            .await
            .expect("project_exists should succeed for dedicated project"),
        "dedicated test project should exist"
    );
    assert!(
        project_client
            .project_exists(DEFAULT_PROJECT)
            .await
            .expect("project_exists should succeed for default project"),
        "default project should exist"
    );
    assert!(
        !project_client
            .project_exists(&format!("{project_name}-missing"))
            .await
            .expect("project_exists should succeed for non-existent project"),
        "non-existent project should not exist"
    );

    // Demonstrate resource isolation from default: the test image alias exists
    // in the default project but is absent in the new project.
    assert!(
        default_client
            .image_alias_exists(TEST_IMAGE_ALIAS)
            .await
            .expect("image_alias_exists should succeed in default project"),
        "test image alias should exist in default project"
    );
    assert!(
        !project_client
            .image_alias_exists(TEST_IMAGE_ALIAS)
            .await
            .expect("image_alias_exists should succeed in custom project"),
        "test image alias from default should not exist in isolated custom project"
    );

    // Instances are also isolated: the dedicated project has no instances.
    let instances = project_client
        .list_instances()
        .await
        .expect("list_instances should succeed in custom project");
    assert!(
        instances.is_empty(),
        "custom project should have no instances"
    );

    default_client
        .delete_project(&project_name)
        .await
        .expect("delete_project should succeed");

    assert!(
        !default_client
            .project_exists(&project_name)
            .await
            .expect("project_exists should succeed after delete"),
        "deleted project should not exist"
    );
}

#[tokio::test]
async fn push_file_into_stopped_instance() {
    let client = client();
    let name = unique_name();

    let create_op = client
        .create_instance(
            &name,
            TEST_IMAGE_ALIAS,
            HashMap::new(),
            sandbox_devices(),
            vec![],
            false,
        )
        .await
        .expect("create_instance should succeed");
    tokio::time::timeout(
        Duration::from_secs(60),
        client.wait_operation(&create_op.id),
    )
    .await
    .expect("create should not time out")
    .expect("create should succeed");

    client
        .push_file_into_instance(&name, "/etc/openshell-test", b"hello from test")
        .await
        .expect("push_file_into_instance should succeed on a stopped container");

    // Verify overwrite works.
    client
        .push_file_into_instance(&name, "/etc/openshell-test", b"updated content")
        .await
        .expect("push_file_into_instance should overwrite an existing file");

    let delete_op = client
        .delete_instance(&name)
        .await
        .expect("delete_instance should succeed");
    tokio::time::timeout(
        Duration::from_secs(30),
        client.wait_operation(&delete_op.id),
    )
    .await
    .expect("delete should not time out")
    .expect("delete should succeed");
}

#[tokio::test]
async fn ensure_supervisor_volume_lifecycle_and_idempotency() {
    let client = client();
    let vol_name = format!("test-sup-vol-{}", unique_name());

    let temp_dir = tempfile::tempdir().unwrap();
    let bin_path = temp_dir.path().join("openshell-sandbox");
    tokio::fs::write(&bin_path, b"dummy-supervisor-binary")
        .await
        .unwrap();

    // 1. Initial creation
    client
        .ensure_supervisor_volume("default", &vol_name, &bin_path)
        .await
        .expect("initial ensure_supervisor_volume should succeed");

    // Check volume exists
    let exists = client
        .storage_pool_volume_exists("default", "custom", &vol_name)
        .await
        .expect("storage_pool_volume_exists should succeed");
    assert!(exists);

    // 2. Second call is an idempotent no-op (short circuits on exists check)
    client
        .ensure_supervisor_volume("default", &vol_name, &bin_path)
        .await
        .expect("second ensure_supervisor_volume should succeed idempotently");

    // Clean up volume
    if let Ok(op) = client
        .delete_storage_pool_volume("default", "custom", &vol_name)
        .await
    {
        let _ = client.wait_operation(&op.id).await;
    }
}

#[tokio::test]
async fn ensure_dhcp_client_volume_lifecycle_and_idempotency() {
    let client = client();
    let vol_name = format!("test-dhcp-vol-{}", unique_name());

    let bin_bytes = b"dummy-udhcpc-binary";
    let script_bytes = b"#!/bin/sh\necho test\n";

    // 1. Initial creation
    client
        .ensure_dhcp_client_volume("default", &vol_name, bin_bytes, script_bytes)
        .await
        .expect("initial ensure_dhcp_client_volume should succeed");

    // Check volume exists
    let exists = client
        .storage_pool_volume_exists("default", "custom", &vol_name)
        .await
        .expect("storage_pool_volume_exists should succeed");
    assert!(exists);

    // Verify files in the provisioned volume have executable permissions (0o755)
    let inst_name = unique_name();
    let mut devices = sandbox_devices();
    let mut vol_device = HashMap::new();
    vol_device.insert("type".to_string(), "disk".to_string());
    vol_device.insert("pool".to_string(), "default".to_string());
    vol_device.insert("source".to_string(), vol_name.clone());
    vol_device.insert("path".to_string(), "/mnt/dhcp".to_string());
    devices.insert("dhcp-vol".to_string(), vol_device);

    let create_op = client
        .create_instance(
            &inst_name,
            TEST_IMAGE_ALIAS,
            HashMap::new(),
            devices,
            vec![],
            true,
        )
        .await
        .expect("create_instance with custom volume should succeed");
    tokio::time::timeout(
        Duration::from_secs(60),
        client.wait_operation(&create_op.id),
    )
    .await
    .expect("create should not time out")
    .expect("create should succeed");

    let (bin_fetched, bin_mode) = client
        .get_file_from_instance(&inst_name, "/mnt/dhcp/udhcpc")
        .await
        .expect("fetching udhcpc from instance should succeed");
    assert_eq!(&bin_fetched[..], bin_bytes);
    assert_eq!(bin_mode & 0o777, 0o755, "udhcpc must have mode 0o755");

    let (script_fetched, script_mode) = client
        .get_file_from_instance(&inst_name, "/mnt/dhcp/udhcpc.script")
        .await
        .expect("fetching udhcpc.script from instance should succeed");
    assert_eq!(&script_fetched[..], script_bytes);
    assert_eq!(
        script_mode & 0o777,
        0o755,
        "udhcpc.script must have mode 0o755"
    );

    let stop_op = client
        .stop_instance(&inst_name, true)
        .await
        .expect("stop_instance should succeed");
    let _ = client.wait_operation(&stop_op.id).await;

    let delete_inst_op = client
        .delete_instance(&inst_name)
        .await
        .expect("delete_instance should succeed");
    let _ = client.wait_operation(&delete_inst_op.id).await;

    // 2. Second call is an idempotent no-op (short circuits on exists check)
    client
        .ensure_dhcp_client_volume("default", &vol_name, bin_bytes, script_bytes)
        .await
        .expect("second ensure_dhcp_client_volume should succeed idempotently");

    // Clean up volume
    if let Ok(op) = client
        .delete_storage_pool_volume("default", "custom", &vol_name)
        .await
    {
        let _ = client.wait_operation(&op.id).await;
    }
}

/// Builds a minimal split image (`metadata.tar.xz` bytes and a
/// `rootfs.squashfs` path) in `dir`, or `None` if `xz` or `mksquashfs` is
/// missing.
async fn build_split_image(dir: &std::path::Path) -> Option<(Vec<u8>, PathBuf)> {
    let metadata_yaml = format!(
        "architecture: \"x86_64\"\ncreation_date: {}\nproperties:\n  description: \"test split image\"\n",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );
    let meta_file_path = dir.join("metadata.yaml");
    tokio::fs::write(&meta_file_path, metadata_yaml.as_bytes())
        .await
        .unwrap();

    let meta_tar_path = dir.join("metadata.tar");
    {
        let tar_file = std::fs::File::create(&meta_tar_path).unwrap();
        let mut builder = tar::Builder::new(tar_file);
        builder
            .append_path_with_name(&meta_file_path, "metadata.yaml")
            .unwrap();
        builder.finish().unwrap();
    }

    let xz = tokio::process::Command::new("xz")
        .args(["-z", "-k", meta_tar_path.to_str().unwrap()])
        .output()
        .await;
    if !matches!(&xz, Ok(output) if output.status.success()) {
        return None;
    }
    let metadata_bytes = tokio::fs::read(dir.join("metadata.tar.xz")).await.unwrap();

    let rootfs_dir = dir.join("rootfs");
    tokio::fs::create_dir(&rootfs_dir).await.unwrap();
    tokio::fs::write(rootfs_dir.join("test.txt"), b"hello-split-image")
        .await
        .unwrap();
    let squashfs_path = dir.join("rootfs.squashfs");
    let mksquashfs = tokio::process::Command::new("mksquashfs")
        .args([
            rootfs_dir.to_str().unwrap(),
            squashfs_path.to_str().unwrap(),
            "-noappend",
        ])
        .output()
        .await;
    if !matches!(&mksquashfs, Ok(output) if output.status.success()) {
        return None;
    }

    Some((metadata_bytes, squashfs_path))
}

async fn fingerprint_of(client: &LxdClient, op_id: &str) -> String {
    let finished_op = tokio::time::timeout(Duration::from_secs(60), client.wait_operation(op_id))
        .await
        .expect("image upload operation should not time out")
        .expect("image upload operation should complete successfully");
    finished_op
        .metadata
        .as_ref()
        .and_then(|m| m.get("fingerprint"))
        .and_then(|f| f.as_str())
        .expect("operation response missing image fingerprint")
        .to_string()
}

#[tokio::test]
async fn create_image_from_split_streams_rootfs() {
    let client = client();
    let temp_dir = tempfile::tempdir().unwrap();
    let Some((metadata_bytes, squashfs_path)) = build_split_image(temp_dir.path()).await else {
        eprintln!(
            "xz or mksquashfs not available; skipping create_image_from_split_streams_rootfs"
        );
        return;
    };

    let op = client
        .create_image_from_split(
            "metadata.tar.xz",
            &metadata_bytes,
            "rootfs.squashfs",
            &squashfs_path,
        )
        .await
        .expect("create_image_from_split should succeed");
    let fingerprint = fingerprint_of(&client, &op.id).await;

    let aliases = client
        .get_image_aliases(&fingerprint)
        .await
        .expect("get_image_aliases should succeed");
    assert!(aliases.is_empty(), "newly imported image has no aliases");

    let alias_name = unique_name();
    client
        .create_image_alias(&alias_name, &fingerprint, None)
        .await
        .expect("create_image_alias should succeed");

    let aliases = client
        .get_image_aliases(&fingerprint)
        .await
        .expect("get_image_aliases should succeed");
    assert_eq!(aliases, vec![alias_name]);

    // Clean up the created image in LXD
    if let Ok(del_op) = client.delete_image(&fingerprint).await {
        let _ = client.wait_operation(&del_op.id).await;
    }
}

/// Every request a project-scoped client makes lands in its project,
/// including the raw uploads (storage volumes from a tarball, split images)
/// and file reads that bypass the JSON request path. Without that, a driver
/// running in a non-default project creates volumes and images in `default`
/// and then waits for their operations in the wrong project.
#[tokio::test]
async fn raw_uploads_and_file_access_stay_in_the_client_project() {
    let _projects = PROJECT_SET_CHANGES.lock().await;
    let default_client = client();
    let project = unique_name();
    default_client
        .create_project(&project)
        .await
        .expect("create_project should succeed");
    let project_client = client().with_project(&project);
    let temp_dir = tempfile::tempdir().unwrap();

    // A volume uploaded as a tarball is created in the project.
    let volume = format!("test-proj-vol-{}", unique_name());
    let bin_path = temp_dir.path().join("openshell-sandbox");
    tokio::fs::write(&bin_path, b"dummy-supervisor-binary")
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(60),
        project_client.ensure_supervisor_volume("default", &volume, &bin_path),
    )
    .await
    .expect("volume upload in a project should not hang")
    .expect("ensure_supervisor_volume in a project should succeed");
    assert!(project_client
        .storage_pool_volume_exists("default", "custom", &volume)
        .await
        .unwrap());
    assert!(
        !default_client
            .storage_pool_volume_exists("default", "custom", &volume)
            .await
            .unwrap(),
        "the volume must not be created in the default project"
    );

    // A split image upload lands in the project too, and an instance created
    // from it there can have files pushed and read back.
    let image_dir = temp_dir.path().join("image");
    tokio::fs::create_dir(&image_dir).await.unwrap();
    let mut fingerprint = None;
    let mut instance = None;
    if let Some((metadata_bytes, squashfs_path)) = build_split_image(&image_dir).await {
        let op = project_client
            .create_image_from_split(
                "metadata.tar.xz",
                &metadata_bytes,
                "rootfs.squashfs",
                &squashfs_path,
            )
            .await
            .expect("create_image_from_split in a project should succeed");
        let image = fingerprint_of(&project_client, &op.id).await;
        fingerprint = Some(image.clone());

        let alias = format!("test-proj-img-{}", unique_name());
        project_client
            .create_image_alias(&alias, &image, None)
            .await
            .expect("the uploaded image should exist in the project");
        assert!(project_client.image_alias_exists(&alias).await.unwrap());

        let name = unique_name();
        let create_op = project_client
            .create_instance(
                &name,
                &alias,
                HashMap::new(),
                sandbox_devices(),
                vec![],
                false,
            )
            .await
            .expect("create_instance in a project should succeed");
        tokio::time::timeout(
            Duration::from_secs(60),
            project_client.wait_operation(&create_op.id),
        )
        .await
        .expect("create should not time out")
        .expect("create should succeed");
        instance = Some(name.clone());

        project_client
            .push_file_into_instance(&name, "/etc/openshell/auth/sandbox.jwt", b"token")
            .await
            .expect("pushing a file into a project instance should succeed");
        let (content, mode) = project_client
            .get_file_from_instance(&name, "/etc/openshell/auth/sandbox.jwt")
            .await
            .expect("reading a file from a project instance should succeed");
        assert_eq!(&content[..], b"token");
        assert_eq!(mode, 0o400);
    } else {
        eprintln!("xz or mksquashfs not available; skipping the image part");
    }

    if let Some(name) = instance {
        if let Ok(op) = project_client.delete_instance(&name).await {
            let _ = project_client.wait_operation(&op.id).await;
        }
    }
    if let Some(fingerprint) = fingerprint {
        if let Ok(op) = project_client.delete_image(&fingerprint).await {
            let _ = project_client.wait_operation(&op.id).await;
        }
    }
    if let Ok(op) = project_client
        .delete_storage_pool_volume("default", "custom", &volume)
        .await
    {
        let _ = project_client.wait_operation(&op.id).await;
    }
    default_client
        .delete_project(&project)
        .await
        .expect("delete_project should succeed");
}

#[tokio::test]
async fn server_architectures_and_verify_architecture() {
    let client = client();
    let archs = client
        .server_architectures()
        .await
        .expect("server_architectures should succeed");
    assert!(
        !archs.is_empty(),
        "server architectures should not be empty"
    );

    // The host architecture must be supported by the local LXD
    let host_arch = std::env::consts::ARCH;
    client
        .verify_architecture(host_arch)
        .await
        .expect("verify_architecture for host_arch should succeed");

    // A completely foreign architecture should be rejected
    let mismatch = client.verify_architecture("nonexistent-arch-12345").await;
    assert!(
        matches!(
            mismatch,
            Err(LxdError::Api {
                status_code: 400,
                ..
            })
        ),
        "verify_architecture for mismatching architecture should return 400 error"
    );
}
