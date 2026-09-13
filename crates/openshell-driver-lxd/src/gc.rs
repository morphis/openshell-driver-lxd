// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clean-up of what the driver leaves behind over time.
//!
//! Every change to how images are converted bumps the conversion revision, and
//! every sandbox image or supervisor release gets its own digest-keyed LXD
//! image or volume. Nothing removed them, so a long-running project collected
//! a gigabyte-sized image per revision and a volume per supervisor release on
//! every pool. A driver killed mid-import also left its scratch directory,
//! several gigabytes, in the work directory.
//!
//! The collector only removes what nothing can still use:
//!
//! - images whose every alias is one of the driver's aliases from an older
//!   conversion revision (a current driver never resolves those; a newer
//!   driver's images are left alone);
//! - supervisor and DHCP-client volumes that no instance uses and that are
//!   not the current supervisor's or DHCP client's;
//!
//! and in LXD only what belongs to the driver's own project: a project
//! without its own images or storage volumes lists the `default` project's,
//! which other users share.
//! - supervisor binaries cached on the host for other digests;
//! - scratch directories older than [`STALE_SCRATCH_AGE`], far beyond any
//!   import the pull timeout lets run.

use std::path::Path;
use std::time::{Duration, SystemTime};

use lxd_client::{Image, LxdClient, StorageVolume};

use crate::image::CONVERSION_REVISION;
use crate::mapping;

/// Age after which a scratch directory is abandoned, not in use.
const STALE_SCRATCH_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Prefixes of the scratch directories the importer creates.
const SCRATCH_PREFIXES: &[&str] = &["openshell-oci-import-", "openshell-supervisor-extract-"];

/// What one collection removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Collected {
    pub images: usize,
    pub volumes: usize,
}

/// Whether `image`, in `project`, belongs to the driver (alias `prefix`) but
/// was converted by an older conversion revision. An image with any other
/// alias is kept.
fn is_stale_image(image: &Image, project: &str, prefix: &str) -> bool {
    image.project == project
        && !image.aliases.is_empty()
        && image
            .aliases
            .iter()
            .all(|alias| is_older_revision_alias(&alias.name, prefix))
}

/// Whether `alias` is the driver's alias for an image converted before the
/// current conversion revision: `<prefix>r<N>-<digest>` with a lower `N`, or
/// the revision-less `<prefix><digest>` of the first releases.
fn is_older_revision_alias(alias: &str, prefix: &str) -> bool {
    let Some(rest) = alias.strip_prefix(prefix) else {
        return false;
    };
    let is_digest = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    if let Some((revision, digest)) = rest.strip_prefix('r').and_then(|r| r.split_once('-')) {
        if let Ok(revision) = revision.parse::<u32>() {
            return revision < CONVERSION_REVISION && is_digest(digest);
        }
    }
    is_digest(rest)
}

/// Whether `volume`, in `project`, is an unused auxiliary volume other than
/// those in `keep`.
fn is_unused_aux_volume(volume: &StorageVolume, project: &str, keep: &[String]) -> bool {
    let aux = volume
        .name
        .starts_with(&mapping::supervisor_volume_name(""))
        || volume
            .name
            .starts_with(&mapping::dhcp_client_volume_name(""));
    volume.project == project && aux && volume.used_by.is_empty() && !keep.contains(&volume.name)
}

/// Removes stale images and unused auxiliary volumes from the project.
///
/// `keep_volumes` names the auxiliary volumes the driver uses now. The caller
/// keeps the driver from provisioning volumes meanwhile. Failures
/// are logged and skipped: whatever is left is retried next time.
pub(crate) async fn collect_lxd(
    lxd: &LxdClient,
    alias_prefix: &str,
    keep_volumes: &[String],
) -> Collected {
    collect(lxd, alias_prefix, Some(keep_volumes)).await
}

async fn collect(
    lxd: &LxdClient,
    alias_prefix: &str,
    keep_volumes: Option<&[String]>,
) -> Collected {
    let mut collected = Collected::default();

    match lxd.list_images().await {
        Ok(images) => {
            for image in images
                .iter()
                .filter(|i| is_stale_image(i, lxd.project(), alias_prefix))
            {
                let removed = async {
                    let op = lxd.delete_image(&image.fingerprint).await?;
                    lxd.wait_operation(&op.id).await
                };
                match removed.await {
                    Ok(_) => {
                        tracing::info!(fingerprint = %image.fingerprint, "removed image from an older conversion revision");
                        collected.images += 1;
                    }
                    Err(e) => {
                        tracing::warn!(fingerprint = %image.fingerprint, %e, "could not remove stale image");
                    }
                }
            }
        }
        Err(e) => tracing::warn!(%e, "could not list images for clean-up"),
    }

    let Some(keep_volumes) = keep_volumes else {
        return collected;
    };
    let pools = match lxd.list_storage_pools().await {
        Ok(pools) => pools,
        Err(e) => {
            tracing::warn!(%e, "could not list storage pools for clean-up");
            return collected;
        }
    };
    for pool in pools {
        let volumes = match lxd.list_custom_volumes(&pool).await {
            Ok(volumes) => volumes,
            Err(e) => {
                tracing::debug!(pool = %pool, %e, "could not list volumes for clean-up");
                continue;
            }
        };
        for volume in volumes
            .iter()
            .filter(|v| is_unused_aux_volume(v, lxd.project(), keep_volumes))
        {
            match lxd
                .delete_custom_volume(&pool, &volume.name, &volume.location)
                .await
            {
                Ok(()) => {
                    tracing::info!(pool = %pool, volume = %volume.name, "removed unused auxiliary volume");
                    collected.volumes += 1;
                }
                // In use again since it was listed, or already gone.
                Err(e) => {
                    tracing::debug!(pool = %pool, volume = %volume.name, %e, "could not remove auxiliary volume");
                }
            }
        }
    }

    collected
}

/// Removes stale images only, leaving every volume alone.
pub(crate) async fn collect_lxd_images_only(lxd: &LxdClient, alias_prefix: &str) -> Collected {
    collect(lxd, alias_prefix, None).await
}

/// Removes host-side leftovers: cached supervisor binaries for digests other
/// than `current_supervisor_digest` (when known), and abandoned scratch
/// directories in `work_dir`. Returns how many entries it removed.
pub(crate) fn collect_host(
    supervisor_cache_dir: &Path,
    current_supervisor_digest: Option<&str>,
    work_dir: &Path,
    now: SystemTime,
) -> usize {
    let mut removed = 0;

    if let Some(current) = current_supervisor_digest {
        let current = current.strip_prefix("sha256:").unwrap_or(current);
        for entry in read_dir(supervisor_cache_dir) {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_digest = name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit());
            if is_digest && name != current && remove(&entry.path()) {
                removed += 1;
            }
        }
    }

    for entry in read_dir(work_dir) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !SCRATCH_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok());
        if age.is_some_and(|age| age > STALE_SCRATCH_AGE) && remove(&entry.path()) {
            removed += 1;
        }
    }

    removed
}

fn read_dir(dir: &Path) -> Vec<std::fs::DirEntry> {
    std::fs::read_dir(dir)
        .map(|entries| entries.filter_map(Result::ok).collect())
        .unwrap_or_default()
}

fn remove(path: &Path) -> bool {
    match std::fs::remove_dir_all(path) {
        Ok(()) => {
            tracing::info!(path = %path.display(), "removed stale host cache entry");
            true
        }
        Err(e) => {
            tracing::warn!(path = %path.display(), %e, "could not remove stale host cache entry");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use lxd_client::ImageAlias;

    use super::*;

    fn image(aliases: &[&str]) -> Image {
        Image {
            fingerprint: "f".repeat(64),
            project: "sandboxes".to_string(),
            aliases: aliases
                .iter()
                .map(|name| ImageAlias {
                    name: (*name).to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn only_older_revisions_of_driver_images_are_stale() {
        let digest = "ab".repeat(32);
        let current = format!("openshell-oci-r{CONVERSION_REVISION}-{digest}");
        let older = format!("openshell-oci-r{}-{digest}", CONVERSION_REVISION - 1);
        let newer = format!("openshell-oci-r{}-{digest}", CONVERSION_REVISION + 1);
        let legacy = format!("openshell-oci-{digest}");
        let stale =
            |aliases: &[&str]| is_stale_image(&image(aliases), "sandboxes", "openshell-oci-");

        assert!(!stale(&[&current]));
        assert!(stale(&[&older]));
        assert!(stale(&[&legacy]));
        // A newer driver's images are its own business.
        assert!(!stale(&[&newer]));
        // Someone else's alias on the image, or no alias at all: not ours.
        assert!(!stale(&[&older, "my-image"]));
        assert!(!stale(&[]));
        assert!(!stale(&["ubuntu-26.04"]));
        assert!(!stale(&["openshell-oci-r1-notadigest"]));
        // Listed from the shared `default` project: not ours either.
        assert!(!is_stale_image(
            &image(&[&older]),
            "other",
            "openshell-oci-"
        ));
    }

    fn volume(name: &str, used_by: &[&str]) -> StorageVolume {
        StorageVolume {
            name: name.to_string(),
            project: "sandboxes".to_string(),
            used_by: used_by.iter().map(|u| (*u).to_string()).collect(),
            location: "rhea".to_string(),
        }
    }

    #[test]
    fn only_unused_other_auxiliary_volumes_go() {
        let keep = vec![
            mapping::supervisor_volume_name("sha256:aaaa"),
            mapping::dhcp_client_volume_name("bbbb"),
        ];

        assert!(is_unused_aux_volume(
            &volume("openshell-supervisor-cccc", &[]),
            "sandboxes",
            &keep
        ));
        assert!(is_unused_aux_volume(
            &volume("openshell-dhcp-client-dddd", &[]),
            "sandboxes",
            &keep
        ));
        assert!(!is_unused_aux_volume(
            &volume("openshell-supervisor-aaaa", &[]),
            "sandboxes",
            &keep
        ));
        assert!(!is_unused_aux_volume(
            &volume("openshell-supervisor-cccc", &["/1.0/instances/sb"]),
            "sandboxes",
            &keep
        ));
        assert!(!is_unused_aux_volume(
            &volume("user-data", &[]),
            "sandboxes",
            &keep
        ));
        // Listed from the shared `default` project.
        assert!(!is_unused_aux_volume(
            &volume("openshell-supervisor-cccc", &[]),
            "other",
            &keep
        ));
    }

    #[test]
    fn host_collection_keeps_the_current_supervisor_and_fresh_scratch() {
        let cache = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let current = "a".repeat(64);
        let older = "b".repeat(64);
        for digest in [&current, &older] {
            std::fs::create_dir_all(cache.path().join(digest)).unwrap();
        }
        std::fs::create_dir_all(cache.path().join("not-a-digest")).unwrap();
        for name in [
            "openshell-oci-import-x1",
            "openshell-supervisor-extract-x2",
            "unrelated",
        ] {
            std::fs::create_dir_all(work.path().join(name)).unwrap();
        }

        // Fresh scratch stays: it may belong to an import running now.
        let removed = collect_host(
            cache.path(),
            Some(&format!("sha256:{current}")),
            work.path(),
            SystemTime::now(),
        );
        assert_eq!(removed, 1);
        assert!(cache.path().join(&current).exists());
        assert!(!cache.path().join(&older).exists());
        assert!(cache.path().join("not-a-digest").exists());
        assert!(work.path().join("openshell-oci-import-x1").exists());

        // A day later the scratch is abandoned; unrelated entries stay.
        let later = SystemTime::now() + STALE_SCRATCH_AGE + Duration::from_secs(60);
        let removed = collect_host(cache.path(), None, work.path(), later);
        assert_eq!(removed, 2);
        assert!(!work.path().join("openshell-oci-import-x1").exists());
        assert!(!work.path().join("openshell-supervisor-extract-x2").exists());
        assert!(work.path().join("unrelated").exists());
        // Without a known current digest no cached binary is touched.
        assert!(cache.path().join(&current).exists());
    }
}
