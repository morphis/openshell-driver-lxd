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
//! - images of the current revision that nothing has been created from for
//!   longer than the configured retention, except the default image's, which
//!   every create without a `template.image` needs;
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

/// LXD's zero time, which it reports for an image nothing was created from.
const LXD_NEVER: &str = "0001-01-01T00:00:00Z";

/// Prefixes of the scratch directories the importer creates.
const SCRATCH_PREFIXES: &[&str] = &["openshell-oci-import-", "openshell-supervisor-extract-"];

/// What one collection removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Collected {
    pub images: usize,
    pub volumes: usize,
    pub acls: usize,
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

/// Whether `alias` is the driver's alias for an image of the current
/// conversion revision.
fn is_current_revision_alias(alias: &str, prefix: &str) -> bool {
    let Some(rest) = alias.strip_prefix(prefix) else {
        return false;
    };
    let Some((revision, digest)) = rest.strip_prefix('r').and_then(|r| r.split_once('-')) else {
        return false;
    };
    revision.parse::<u32>() == Ok(CONVERSION_REVISION)
        && digest.len() == 64
        && digest.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `image`, in `project`, is one of the driver's current-revision
/// images that nothing has been created from for `retention`.
///
/// An image is identified by content digest, so re-importing one that is
/// wanted again is correct, only slow. `keep_aliases` names the images that
/// slowness would be unacceptable for — the default image above all, which
/// every create without a `template.image` of its own resolves.
///
/// `last_used_at` is what LXD stamps when an instance is created from the
/// image, so an image last used before the cut-off has no sandbox younger than
/// it; sandboxes created earlier hold their own copy of the rootfs and do not
/// need the image. An image nothing has ever been created from is judged by
/// when it was uploaded instead, and one whose timestamps LXD does not report
/// is left alone.
fn is_evictable_image(
    image: &Image,
    project: &str,
    prefix: &str,
    keep_aliases: &[String],
    now: SystemTime,
    retention: Duration,
) -> bool {
    if retention.is_zero() || image.project != project || image.aliases.is_empty() {
        return false;
    }
    if !image
        .aliases
        .iter()
        .all(|alias| is_current_revision_alias(&alias.name, prefix))
    {
        return false;
    }
    if image
        .aliases
        .iter()
        .any(|alias| keep_aliases.contains(&alias.name))
    {
        return false;
    }

    let used = image
        .last_used_at
        .as_deref()
        .filter(|stamp| *stamp != LXD_NEVER)
        .or(image.uploaded_at.as_deref());
    let Some(used) = used.and_then(parse_rfc3339) else {
        return false;
    };
    now.duration_since(used).is_ok_and(|age| age > retention)
}

/// Parses the RFC 3339 timestamps LXD reports into a [`SystemTime`].
///
/// Anything that does not parse returns None, which the caller reads as
/// "leave this image alone".
fn parse_rfc3339(value: &str) -> Option<SystemTime> {
    Some(SystemTime::from(
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()?,
    ))
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
    images: ImageRetention<'_>,
) -> Collected {
    collect(lxd, alias_prefix, Some(keep_volumes), images).await
}

/// How long an unused current-revision image is kept, and which aliases are
/// never collected whatever their age.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ImageRetention<'a> {
    /// Zero keeps every current-revision image, whatever its age.
    pub retention: Duration,
    pub keep_aliases: &'a [String],
}

async fn collect(
    lxd: &LxdClient,
    alias_prefix: &str,
    keep_volumes: Option<&[String]>,
    images: ImageRetention<'_>,
) -> Collected {
    let mut collected = Collected::default();
    let now = SystemTime::now();

    match lxd.list_images().await {
        Ok(listed) => {
            for (image, why) in listed.iter().filter_map(|i| {
                if is_stale_image(i, lxd.project(), alias_prefix) {
                    Some((i, "an older conversion revision"))
                } else if is_evictable_image(
                    i,
                    lxd.project(),
                    alias_prefix,
                    images.keep_aliases,
                    now,
                    images.retention,
                ) {
                    Some((i, "no use within the retention window"))
                } else {
                    None
                }
            }) {
                let removed = async {
                    let op = lxd.delete_image(&image.fingerprint).await?;
                    lxd.wait_operation(&op.id).await
                };
                match removed.await {
                    Ok(_) => {
                        tracing::info!(fingerprint = %image.fingerprint, reason = why, "removed image");
                        collected.images += 1;
                    }
                    Err(e) => {
                        tracing::warn!(fingerprint = %image.fingerprint, %e, "could not remove image");
                    }
                }
            }
        }
        Err(e) => tracing::warn!(%e, "could not list images for clean-up"),
    }

    collected.acls += collect_sandbox_acls(lxd).await;

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

/// Removes per-sandbox ACLs nothing references any more.
///
/// A sandbox's own ACL goes with it on delete, but a delete that raced LXD
/// still holding the NIC leaves one behind, and so does a driver that died
/// mid-create. An ACL with an empty `used_by` grants nothing to anything, so
/// removing it is safe; one still in use LXD refuses to delete anyway.
///
/// Only the driver's own prefix is considered, and only in its own project,
/// so an operator's ACLs are never touched.
async fn collect_sandbox_acls(lxd: &LxdClient) -> usize {
    let acls = match lxd.list_network_acls().await {
        Ok(acls) => acls,
        Err(e) => {
            tracing::warn!(%e, "could not list network ACLs for clean-up");
            return 0;
        }
    };
    let mut removed = 0;
    for (name, _) in acls.into_iter().filter(|(name, used_by)| {
        crate::egress::SANDBOX_ACL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
            && used_by.is_empty()
    }) {
        match lxd.delete_network_acl(&name).await {
            Ok(()) => {
                tracing::info!(acl = %name, "removed a sandbox ACL nothing uses");
                removed += 1;
            }
            // In use again since it was listed, or already gone.
            Err(e) => tracing::debug!(acl = %name, %e, "could not remove sandbox ACL"),
        }
    }
    removed
}

/// Removes collectable images only, leaving every volume alone.
pub(crate) async fn collect_lxd_images_only(
    lxd: &LxdClient,
    alias_prefix: &str,
    images: ImageRetention<'_>,
) -> Collected {
    collect(lxd, alias_prefix, None, images).await
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
    use std::time::UNIX_EPOCH;

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
            last_used_at: None,
            uploaded_at: None,
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

    fn aged_image(alias: &str, last_used: Option<&str>, uploaded: Option<&str>) -> Image {
        let mut image = image(&[alias]);
        image.last_used_at = last_used.map(str::to_string);
        image.uploaded_at = uploaded.map(str::to_string);
        image
    }

    fn at(stamp: &str) -> SystemTime {
        parse_rfc3339(stamp).expect("test timestamp parses")
    }

    #[test]
    fn rfc3339_timestamps_parse_to_the_right_instant() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(UNIX_EPOCH));
        assert_eq!(
            parse_rfc3339("1970-01-02T00:00:01Z"),
            Some(UNIX_EPOCH + Duration::from_secs(86_401))
        );
        // LXD stamps a fractional part and sometimes a numeric offset.
        assert_eq!(
            parse_rfc3339("2026-09-21T05:36:00.123456789Z"),
            Some(UNIX_EPOCH + Duration::new(1_789_968_960, 123_456_789))
        );
        assert_eq!(
            parse_rfc3339("2026-09-21T07:36:00+02:00"),
            parse_rfc3339("2026-09-21T05:36:00Z")
        );
        assert_eq!(
            parse_rfc3339("2026-09-21T03:36:00-02:00"),
            parse_rfc3339("2026-09-21T05:36:00Z")
        );
        // A leap year's end, to catch the civil-date arithmetic.
        assert_eq!(
            parse_rfc3339("2024-12-31T23:59:59Z").map(|t| t + Duration::from_secs(1)),
            parse_rfc3339("2025-01-01T00:00:00Z")
        );

        for bad in [
            "",
            "not a date",
            "2026-09-21",
            "2026-13-01T00:00:00Z",
            "2026-09-21T25:00:00Z",
            "2026-09-21T05:36:00+0200",
        ] {
            assert!(parse_rfc3339(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn current_revision_images_go_only_once_unused_for_the_retention() {
        let digest = "ab".repeat(32);
        let alias = format!("openshell-oci-r{CONVERSION_REVISION}-{digest}");
        let week = Duration::from_secs(7 * 24 * 60 * 60);
        let now = at("2026-09-21T00:00:00Z");
        let evictable = |image: &Image, keep: &[String], retention: Duration| {
            is_evictable_image(image, "sandboxes", "openshell-oci-", keep, now, retention)
        };

        let stale = aged_image(&alias, Some("2026-09-01T00:00:00Z"), None);
        let fresh = aged_image(&alias, Some("2026-09-20T00:00:00Z"), None);
        assert!(evictable(&stale, &[], week));
        assert!(!evictable(&fresh, &[], week));

        // Retention 0 keeps everything, which is how an unresolvable default
        // image disables collection by age entirely.
        assert!(!evictable(&stale, &[], Duration::ZERO));

        // The default image is kept however long it has sat unused.
        assert!(!evictable(&stale, std::slice::from_ref(&alias), week));

        // Never used: judged by when it was uploaded instead.
        let never_used = aged_image(&alias, Some(LXD_NEVER), Some("2026-09-01T00:00:00Z"));
        assert!(evictable(&never_used, &[], week));
        let just_uploaded = aged_image(&alias, Some(LXD_NEVER), Some("2026-09-20T00:00:00Z"));
        assert!(!evictable(&just_uploaded, &[], week));

        // No timestamps at all, or ones that do not parse: left alone.
        assert!(!evictable(&aged_image(&alias, None, None), &[], week));
        assert!(!evictable(
            &aged_image(&alias, Some("soon"), None),
            &[],
            week
        ));

        // Not ours, or shared from the `default` project: left alone.
        let foreign = aged_image("ubuntu-26.04", Some("2026-09-01T00:00:00Z"), None);
        assert!(!evictable(&foreign, &[], week));
        let mut shared = aged_image(&alias, Some("2026-09-01T00:00:00Z"), None);
        shared.project = "other".to_string();
        assert!(!evictable(&shared, &[], week));
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
