// SPDX-License-Identifier: AGPL-3.0-or-later

//! `--project`: everything the driver creates and reports stays inside its
//! LXD project.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::Code;

use crate::harness::*;

/// An LXD project that is deleted, with everything in it, when dropped.
struct Project {
    name: String,
    own_images: bool,
}

impl Project {
    /// Creates a project. `own_images: false` shares the default project's
    /// images, so the already-imported sandbox image is usable without a
    /// fresh import.
    fn create(own_images: bool) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("odl-p{:x}", nanos % 0xffff_ffff_ffff);
        let images = format!("features.images={own_images}");
        lxc(&[
            "project",
            "create",
            &name,
            "-c",
            &images,
            "-c",
            "features.profiles=false",
        ]);
        Self { name, own_images }
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let project = self.name.as_str();
        let list = |args: &[&str]| -> Vec<String> {
            lxc_output(args)
                .stdout
                .split(|b| *b == b'\n')
                .map(|l| String::from_utf8_lossy(l).trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        };
        for instance in list(&["list", "--project", project, "--format", "csv", "-c", "n"]) {
            let _ = lxc_output(&["delete", "--force", &instance, "--project", project]);
        }
        for line in list(&[
            "storage",
            "volume",
            "list",
            "default",
            "--project",
            project,
            "--format",
            "csv",
        ]) {
            // Projects are created with their own storage volumes (LXD's
            // default), so this lists only volumes the driver made in it.
            let mut fields = line.split(',');
            if let (Some("custom"), Some(volume)) = (fields.next(), fields.next()) {
                let _ = lxc_output(&[
                    "storage",
                    "volume",
                    "delete",
                    "default",
                    volume,
                    "--project",
                    project,
                ]);
            }
        }
        // A project without its own images lists the default project's,
        // which are not ours to delete.
        if self.own_images {
            for fingerprint in list(&[
                "image",
                "list",
                "--project",
                project,
                "--format",
                "csv",
                "-c",
                "F",
            ]) {
                let _ = lxc_output(&["image", "delete", &fingerprint, "--project", project]);
            }
        }
        let _ = lxc_output(&["project", "delete", project]);
    }
}

#[tokio::test]
async fn driver_refuses_to_start_without_its_project() {
    let driver = Driver::spawn(DriverOptions {
        project: "odl-no-such-project".to_string(),
        ..Default::default()
    });

    let status = driver
        .wait_exit(Duration::from_secs(30))
        .await
        .expect("driver should exit when its project is missing");
    assert!(!status.success());
    assert!(
        driver
            .log()
            .contains("configured LXD project does not exist"),
        "log:\n{}",
        driver.log()
    );
}

/// A driver confined to a project creates, reports and deletes its sandboxes
/// there and nowhere else, including the supervisor and DHCP-client volumes
/// it provisions.
#[tokio::test]
async fn sandboxes_stay_inside_the_driver_project() {
    let project = Project::create(false);
    let in_project = Driver::start_with(DriverOptions {
        project: project.name.clone(),
        ..Default::default()
    })
    .await;
    let in_default = Driver::start().await;
    let name = unique_name("proj");
    let id = sandbox_id(&name);
    let _cleanup = in_project.cleanup(&[&name]);

    in_project.create_running(&name).await;

    // The volumes the sandbox mounts were provisioned in the project.
    let volumes = lxc(&[
        "storage",
        "volume",
        "list",
        "default",
        "--project",
        &project.name,
        "--format",
        "csv",
        "-c",
        "tn",
    ]);
    for prefix in [
        "custom,openshell-supervisor-",
        "custom,openshell-dhcp-client-",
    ] {
        assert!(
            volumes.lines().any(|line| line.starts_with(prefix)),
            "no {prefix}* volume in {}: {volumes}",
            project.name
        );
    }

    assert!(lxd_in(&project.name).get_instance(&name).await.is_ok());
    assert!(
        lxd().get_instance(&name).await.is_err(),
        "the sandbox must not appear in the default project"
    );
    assert!(in_project.list().await.iter().any(|s| s.id == id));
    assert!(!in_default.list().await.iter().any(|s| s.id == id));
    let status = in_default.get(&name).await.expect_err("other project");
    assert_eq!(status.code(), Code::NotFound);

    // Events from the project reach the driver watching it.
    let mut watch = in_project.watch().await;
    in_project.exit_supervisor(&name, 0).await;
    watch.expect_snapshot(&id, "False", "ContainerExited").await;

    assert!(in_project.delete(&name).await.expect("delete in project"));
    assert!(lxd_in(&project.name).get_instance(&name).await.is_err());
}

/// In a project with its own images, the converted image is uploaded into
/// that project and nothing leaks into `default`.
///
/// The import is driven through the startup pre-warm, which imports without
/// provisioning volumes, so this checks the image upload on its own.
#[tokio::test]
async fn cold_import_lands_in_a_project_with_its_own_images() {
    let project = Project::create(true);
    let prefix = format!("{}-", project.name);
    let driver = Driver::start_with(DriverOptions {
        project: project.name.clone(),
        default_image: "ghcr.io/nvidia/openshell/supervisor:0.0.116".to_string(),
        image_cache_alias_prefix: prefix.clone(),
        extra_args: vec!["--image-pull-timeout-secs".into(), "30".into()],
        ..Default::default()
    })
    .await;

    // The pre-warm runs in the background; wait for its outcome.
    eventually(
        Duration::from_secs(120),
        "the pre-warm to finish",
        || async {
            let log = driver.log();
            (log.contains("default sandbox image ready") || log.contains("could not pre-warm"))
                .then_some(())
        },
    )
    .await;

    // Remove any image leaked into the default project before asserting. The
    // driver describes an image by its alias, which carries this project's
    // name, so only this test's leaks match.
    let leaked: Vec<String> = lxc(&["image", "list", "--format", "csv", "-c", "Fd"])
        .lines()
        .filter(|line| line.contains(&project.name))
        .filter_map(|line| line.split(',').next())
        .map(str::to_string)
        .collect();
    for fingerprint in &leaked {
        let _ = lxc_output(&["image", "delete", fingerprint]);
    }

    assert!(
        driver.log().contains("default sandbox image ready"),
        "pre-warm import into {} failed; log:\n{}",
        project.name,
        driver.log()
    );
    assert!(leaked.is_empty(), "images leaked into default: {leaked:?}");
    let aliases = lxc(&[
        "image",
        "alias",
        "list",
        "--project",
        &project.name,
        "--format",
        "csv",
    ]);
    assert!(
        aliases.lines().any(|line| line.starts_with(&prefix)),
        "no {prefix}* alias in {}: {aliases}",
        project.name
    );
}

/// Clean-up at start-up removes images from older conversion revisions and
/// unused auxiliary volumes, and keeps images of the current revision and
/// volumes that are not the driver's. Runs in its own project, where no
/// other test's driver is working.
#[tokio::test]
async fn cleanup_removes_what_the_driver_no_longer_uses() {
    let project = Project::create(true);
    let prefix = format!("{}-", project.name);
    let digest = "cd".repeat(32);
    let stale_alias = format!("{prefix}r1-{digest}");
    let current_alias = format!(
        "{prefix}r{}-{digest}",
        openshell_driver_lxd::image::CONVERSION_REVISION
    );
    import_tiny_image(&project.name, &stale_alias, "stale");
    import_tiny_image(&project.name, &current_alias, "current");

    for volume in [
        "openshell-supervisor-0000",
        "openshell-dhcp-client-0000",
        "user-data",
    ] {
        lxc(&[
            "storage",
            "volume",
            "create",
            "default",
            volume,
            "--project",
            &project.name,
        ]);
    }

    let driver = Driver::start_with(DriverOptions {
        project: project.name.clone(),
        image_cache_alias_prefix: prefix,
        default_image: "ghcr.io/nvidia/openshell/supervisor:0.0.116".to_string(),
        cleanup: true,
        ..Default::default()
    })
    .await;
    eventually(Duration::from_secs(300), "clean-up to finish", || async {
        driver.log().contains("clean-up finished").then_some(())
    })
    .await;

    let volumes = lxc(&[
        "storage",
        "volume",
        "list",
        "default",
        "--project",
        &project.name,
        "--format",
        "csv",
        "-c",
        "n",
    ]);
    assert!(
        !volumes.contains("-0000"),
        "unused auxiliary volumes should be gone: {volumes}"
    );
    assert!(volumes.contains("user-data"), "{volumes}");

    let images = lxc(&[
        "image",
        "list",
        "--project",
        &project.name,
        "--format",
        "csv",
        "-c",
        "l",
    ]);
    assert!(!images.contains(&stale_alias), "{images}");
    assert!(images.contains(&current_alias), "{images}");
}

/// Imports a minimal image, distinct per `content`, under `alias`.
fn import_tiny_image(project: &str, alias: &str, content: &str) {
    let dir = tempfile::tempdir().expect("temp dir");
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    std::fs::write(rootfs.join("content"), content).unwrap();
    std::fs::write(
        dir.path().join("metadata.yaml"),
        "architecture: x86_64\ncreation_date: 1\n",
    )
    .unwrap();
    let run = |program: &str, args: &[&str]| {
        let output = std::process::Command::new(program)
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap_or_else(|e| panic!("{program}: {e}"));
        assert!(output.status.success(), "{program} {args:?}: {output:?}");
    };
    run("tar", &["-cJf", "meta.tar.xz", "metadata.yaml"]);
    run(
        "mksquashfs",
        &["rootfs", "rootfs.squashfs", "-noappend", "-quiet"],
    );
    let meta = dir.path().join("meta.tar.xz");
    let squashfs = dir.path().join("rootfs.squashfs");
    lxc(&[
        "image",
        "import",
        meta.to_str().unwrap(),
        squashfs.to_str().unwrap(),
        "--alias",
        alias,
        "--project",
        project,
    ]);
}
