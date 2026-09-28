// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCI image resolution and import through CreateSandbox: failures must be
//! reported and leave nothing behind, and imports must be cached by digest.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tonic::Code;

use crate::harness::*;

/// A small, pinned image that is cheap to import cold. It is BusyBox-only, so
/// a sandbox from it does not stay up; these tests only care about the image.
const SMALL_IMAGE: &str = "ghcr.io/nvidia/openshell/supervisor:0.0.116";

/// Index digest of [`SMALL_IMAGE`].
const SMALL_IMAGE_INDEX_DIGEST: &str =
    "c8c42aef16c200063e32cbf72e553e4ead027085427b555efafd95063ecead42";

/// An alias prefix no other test or run uses, so the import is always cold.
fn fresh_alias_prefix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("odl-test-{:x}-", nanos % 0xffff_ffff_ffff)
}

/// Deletes every image with an alias starting with `prefix` when dropped.
struct ImageCleanup(String);

impl Drop for ImageCleanup {
    fn drop(&mut self) {
        for alias in aliases_with_prefix(&self.0) {
            let _ = lxc_output(&["image", "delete", &alias]);
        }
    }
}

fn aliases_with_prefix(prefix: &str) -> Vec<String> {
    lxc(&["image", "alias", "list", "--format", "csv"])
        .lines()
        .filter_map(|line| line.split(',').next())
        .filter(|alias| alias.starts_with(prefix))
        .map(str::to_string)
        .collect()
}

/// Driver options for a cold import: a fresh alias prefix, and a work dir of
/// its own so leftovers from other tests' imports cannot be mistaken for ours.
///
/// The default image fails to resolve at once: with a fresh prefix, a real
/// one would be cold-imported by the startup pre-warm, which blocks serving.
fn cold_import_options() -> DriverOptions {
    let prefix = fresh_alias_prefix();
    DriverOptions {
        default_image: "registry.invalid/openshell/no-prewarm:latest".to_string(),
        supervisor_image: Some(SMALL_IMAGE.to_string()),
        image_work_dir: scratch_root().join(format!("work-{prefix}")),
        image_cache_alias_prefix: prefix,
        ..Default::default()
    }
}

/// True when nothing from a conversion is left in the driver's work dir.
fn work_dir_is_empty(options: &DriverOptions) -> bool {
    std::fs::read_dir(&options.image_work_dir)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true)
}

async fn create_from(driver: &Driver, name: &str, image: &str) -> Result<(), tonic::Status> {
    let mut request = sandbox(name);
    template_mut(&mut request).image = image.to_string();
    driver.create(request).await
}

/// Failures to resolve an image fail CreateSandbox promptly, name the image,
/// and leave no instance and no scratch files.
#[tokio::test]
async fn unresolvable_images_fail_cleanly() {
    let options = cold_import_options();
    let driver = Driver::start_with(options.clone()).await;

    for image in [
        "ghcr.io/nvidia/openshell-community/sandboxes/base:odl-no-such-tag",
        "registry.invalid/openshell/nope:latest",
    ] {
        let name = unique_name("badimg");
        let _cleanup = driver.cleanup(&[&name]);

        let started = Instant::now();
        let status = create_from(&driver, &name, image)
            .await
            .expect_err("an unresolvable image should fail the create");

        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{image}: failing took {:?}",
            started.elapsed()
        );
        assert!(status.message().contains(image), "{image}: {status}");
        assert!(
            lxd().get_instance(&name).await.is_err(),
            "{image}: instance left behind"
        );
    }
    assert!(
        work_dir_is_empty(&options),
        "image work dir should be cleaned up"
    );
}

/// A reference that can never be valid is the caller's mistake:
/// `InvalidArgument`, and nothing is created.
#[tokio::test]
async fn malformed_image_reference_is_invalid_argument() {
    let driver = Driver::start().await;
    let name = unique_name("malformed");
    let _cleanup = driver.cleanup(&[&name]);

    let status = create_from(&driver, &name, "UPPER/Case::bad")
        .await
        .expect_err("a malformed reference should fail the create");
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert!(lxd().get_instance(&name).await.is_err());
}

/// A cold import converts the image once, keyed by digest; later creates
/// from the same image reuse it. The converted image carries the injected
/// init script.
#[tokio::test]
async fn imports_are_cached_by_digest() {
    let options = cold_import_options();
    let prefix = options.image_cache_alias_prefix.clone();
    let _images = ImageCleanup(prefix.clone());
    let driver = Driver::start_with(options.clone()).await;
    let first = unique_name("cold");
    let second = unique_name("warm");
    let _cleanup = driver.cleanup(&[&first, &second]);

    // The sandbox exits (BusyBox has no loader for the stand-in), which is
    // irrelevant here; only the image and instance creation matter.
    let _ = create_from(&driver, &first, SMALL_IMAGE).await;
    let aliases = aliases_with_prefix(&prefix);
    assert_eq!(aliases.len(), 1, "one image per digest: {aliases:?}");
    assert!(
        work_dir_is_empty(&options),
        "image work dir should be cleaned up"
    );

    let (_, mode) = lxd()
        .get_file_from_instance(&first, "/openshell-init.sh")
        .await
        .expect("the converted image should contain the init script");
    assert_eq!(mode & 0o111, 0o111, "init script must be executable");

    let _ = create_from(&driver, &second, SMALL_IMAGE).await;
    assert_eq!(aliases_with_prefix(&prefix), aliases);
    assert!(
        driver.log().contains("image cache hit"),
        "second create should hit the cache"
    );
    assert_eq!(driver.log().matches("image cache miss").count(), 1);
}

/// A converted image keeps the file ownership its layers specify. The
/// supervisor runs the workload as the image's `sandbox` user, which must own
/// and be able to write its workdir — as it would under Docker.
#[tokio::test]
async fn converted_image_keeps_file_ownership() {
    let driver = Driver::start().await;
    let name = unique_name("owner");
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    let exec = |script: &str| {
        let output = lxc_output(&["exec", &name, "--", "sh", "-c", script]);
        assert!(
            output.status.success(),
            "{script}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };

    let sandbox_ids = exec("echo $(id -u sandbox):$(id -g sandbox)");
    assert_ne!(
        sandbox_ids, "0:0",
        "the base image defines a non-root sandbox user"
    );
    assert_eq!(
        exec("stat -c %u:%g /sandbox"),
        sandbox_ids,
        "/sandbox owner"
    );
    assert_eq!(
        exec("stat -c %u:%g /sandbox/.bashrc"),
        sandbox_ids,
        "files the image gives the sandbox user"
    );
    assert_eq!(
        exec("stat -c %u:%g /etc/passwd"),
        "0:0",
        "system files stay root's"
    );

    let uid = sandbox_ids.split(':').next().unwrap();
    let output = lxc_output(&[
        "exec",
        &name,
        "--user",
        uid,
        "--",
        "sh",
        "-c",
        "echo ok > /sandbox/.written",
    ]);
    assert!(
        output.status.success(),
        "the sandbox user cannot write its workdir: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A reference pinned by both tag and digest imports: skopeo rejects that
/// form, so the driver must resolve it by digest alone.
#[tokio::test]
async fn tag_and_digest_pinned_reference_imports() {
    let options = cold_import_options();
    let prefix = options.image_cache_alias_prefix.clone();
    let _images = ImageCleanup(prefix.clone());
    let driver = Driver::start_with(options).await;
    let name = unique_name("pinned");
    let _cleanup = driver.cleanup(&[&name]);

    let pinned = format!("{SMALL_IMAGE}@sha256:{SMALL_IMAGE_INDEX_DIGEST}");
    if let Err(status) = create_from(&driver, &name, &pinned).await {
        assert_ne!(status.code(), Code::Internal, "{status}");
    }

    assert!(
        lxd().get_instance(&name).await.is_ok(),
        "{name} should exist"
    );
    assert_eq!(aliases_with_prefix(&prefix).len(), 1);
}

/// Two creates of the same uncached image at once share one import.
#[tokio::test]
async fn concurrent_creates_share_one_import() {
    let options = cold_import_options();
    let prefix = options.image_cache_alias_prefix.clone();
    let _images = ImageCleanup(prefix.clone());
    let driver = Driver::start_with(options).await;
    let a = unique_name("conca");
    let b = unique_name("concb");
    let _cleanup = driver.cleanup(&[&a, &b]);

    let (ra, rb) = tokio::join!(
        create_from(&driver, &a, SMALL_IMAGE),
        create_from(&driver, &b, SMALL_IMAGE)
    );

    for (name, result) in [(&a, ra), (&b, rb)] {
        if let Err(status) = result {
            assert_ne!(
                status.code(),
                Code::Internal,
                "{name} failed on the shared import: {status}"
            );
        }
        assert!(
            lxd().get_instance(name).await.is_ok(),
            "{name} should exist"
        );
    }
    assert_eq!(aliases_with_prefix(&prefix).len(), 1);
    assert_eq!(driver.log().matches("image cache miss").count(), 1);
}
