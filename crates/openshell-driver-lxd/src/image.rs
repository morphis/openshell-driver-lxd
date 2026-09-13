// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCI image resolution, caching, and LXD image importing.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use lxd_client::LxdClient;
use regex::Regex;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::error::DriverError;

/// Default prefix for digest-derived LXD image aliases.
pub const DEFAULT_CACHE_ALIAS_PREFIX: &str = "openshell-oci-";

/// Canonical path inside the guest rootfs for the injected PID 1 init script.
pub(crate) const GUEST_INIT_SCRIPT_PATH: &str = "/openshell-init.sh";

/// The init LXD starts in a container. LXD has no instance option for a
/// container's init; the only other way to change it is `lxc.init.cmd` in
/// `raw.lxc`, a low-level key restricted projects refuse. Pointing this path
/// at [`GUEST_INIT_SCRIPT_PATH`] in the converted image lets a sandbox boot in
/// a restricted project.
pub(crate) const GUEST_INIT_PATH: &str = "/sbin/init";

/// How many symlinks resolving a path inside a rootfs may follow, as the
/// kernel's limit for a path lookup.
const MAX_SYMLINK_HOPS: usize = 40;

/// Bundled POSIX/busybox init script injected into converted rootfs images.
const INIT_SCRIPT_CONTENTS: &str = include_str!("../assets/openshell-init.sh");

static OCI_REF_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    // Strict OCI reference grammar:
    // [docker://][domain[:port]/]path[:tag][@sha256:digest]
    // Rejects whitespace, control characters, shell metacharacters.
    Regex::new(r"^(?:docker://)?(?:(?:[a-zA-Z0-9.-]+(?::[0-9]+)?/)?(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*)(?::[a-zA-Z0-9_.-]+)?(?:@sha256:[a-fA-F0-9]{64})?$")
        .expect("valid regex")
});

/// Strips an optional `docker://` transport prefix from a reference.
///
/// skopeo accepts both bare OCI references and `docker://`-prefixed ones, but
/// the importer always constructs its own `docker://` target, so any user-supplied
/// scheme must be removed before building that target.
pub fn strip_docker_scheme(reference: &str) -> &str {
    reference.strip_prefix("docker://").unwrap_or(reference)
}

/// Validates an OCI reference against a strict grammar.
///
/// Disallows shell metacharacters, whitespace, control characters, or invalid formats.
/// An optional leading `docker://` transport prefix is accepted.
///
/// A reference that fails this check can never be imported, so it is the
/// caller's mistake: [`DriverError::InvalidArgument`], not an import failure.
pub fn validate_reference(reference: &str) -> Result<(), DriverError> {
    if reference.is_empty() {
        return Err(DriverError::InvalidArgument(
            "image reference cannot be empty".to_string(),
        ));
    }
    if !OCI_REF_REGEX.is_match(reference) {
        return Err(DriverError::InvalidArgument(format!(
            "invalid OCI image reference: {reference:?}"
        )));
    }
    Ok(())
}

/// Revision of the OCI-to-LXD conversion, part of every cache alias.
///
/// Bump it whenever the conversion produces a different image for the same
/// OCI digest, so images converted the old way are imported again instead of
/// being reused. Revision 2 keeps the image's file ownership; revision 3 boots
/// the init script through `/sbin/init`, which also takes the nameserver from
/// the network, reaches gateways by IPv6 address or host name and probes an
/// https gateway the way the supervisor connects to it.
pub const CONVERSION_REVISION: u32 = 3;

/// Returns the deterministic LXD cache alias for the given content digest.
///
/// Strips any `sha256:` prefix and returns
/// `<prefix>r<conversion revision>-<full 64 hex chars>`. Does not truncate the
/// digest, ensuring distinct digests never collide.
pub fn cache_alias(digest: &str) -> String {
    cache_alias_with_prefix(DEFAULT_CACHE_ALIAS_PREFIX, digest)
}

/// Returns the cache alias using a custom prefix.
pub fn cache_alias_with_prefix(prefix: &str, digest: &str) -> String {
    let clean = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("{prefix}r{CONVERSION_REVISION}-{clean}")
}

/// Extended attribute in which `umoci unpack --rootless` records each file's
/// owner from the image layers, because it does not chown — neither as an
/// unprivileged user nor as root.
const ROOTLESS_OWNER_XATTR: &str = "user.rootlesscontainers";

/// umoci's "unchanged" id in [`ROOTLESS_OWNER_XATTR`]: the file keeps the
/// unpacking user's id, which stands for root.
const ROOTLESS_NOOP_ID: u32 = u32::MAX;

/// Decodes a [`ROOTLESS_OWNER_XATTR`] value, the rootlesscontainers protobuf
/// `Resource { uint32 uid = 1; uint32 gid = 2; }`, into `(uid, gid)`.
///
/// A missing field and the no-op id both mean root.
pub(crate) fn decode_rootless_owner(bytes: &[u8]) -> Option<(u32, u32)> {
    let mut uid = 0;
    let mut gid = 0;
    let mut rest = bytes;
    while let Some((&key, tail)) = rest.split_first() {
        // Only varint fields are expected (wire type 0).
        if key & 0x7 != 0 {
            return None;
        }
        let mut value: u64 = 0;
        let mut shift = 0;
        let mut consumed = 0;
        for &byte in tail {
            consumed += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                return None;
            }
        }
        if consumed == 0 || tail[consumed - 1] & 0x80 != 0 {
            return None;
        }
        let id = u32::try_from(value).ok()?;
        let id = if id == ROOTLESS_NOOP_ID { 0 } else { id };
        match key >> 3 {
            1 => uid = id,
            2 => gid = id,
            _ => {}
        }
        rest = &tail[consumed..];
    }
    Some((uid, gid))
}

/// Reads [`ROOTLESS_OWNER_XATTR`] from `path` without following symlinks.
#[cfg(target_os = "linux")]
fn read_rootless_owner(path: &Path) -> std::io::Result<Option<(u32, u32)>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let c_name = CString::new(ROOTLESS_OWNER_XATTR).expect("static name has no NUL");
    let mut buf = [0u8; 64];
    // SAFETY: both strings are NUL-terminated and outlive the call, and the
    // buffer length passed is the buffer's real length.
    let len = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if len < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            // No record (a root-owned file) or no xattr support (a symlink).
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(None),
            _ => Err(err),
        };
    }
    let len = usize::try_from(len).expect("non-negative length");
    decode_rootless_owner(&buf[..len]).map(Some).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("malformed {ROOTLESS_OWNER_XATTR} on {}", path.display()),
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn read_rootless_owner(_path: &Path) -> std::io::Result<Option<(u32, u32)>> {
    Ok(None)
}

/// Quotes a rootfs-relative path for a mksquashfs pseudo definition.
fn pseudo_quote(path: &[u8]) -> Vec<u8> {
    let mut quoted = Vec::with_capacity(path.len() + 2);
    quoted.push(b'"');
    for &byte in path {
        if byte == b'"' || byte == b'\\' {
            quoted.push(b'\\');
        }
        quoted.push(byte);
    }
    quoted.push(b'"');
    quoted
}

/// Writes a mksquashfs pseudo file that gives every entry under `rootfs` the
/// owner the image layers specify.
///
/// `umoci unpack --rootless` leaves every file owned by the unpacking user and
/// records the real owner in [`ROOTLESS_OWNER_XATTR`]. Without restoring it,
/// every file in the sandbox would belong to root (or to whoever ran the
/// driver), and the sandbox user could not write to its own workdir. Each
/// entry gets an `m` (modify) definition with its current mode and its
/// recorded owner, root when there is no record. Returns the number of
/// entries.
pub(crate) fn write_ownership_pseudo_file(
    rootfs: &Path,
    pseudo_file: &Path,
) -> Result<usize, DriverError> {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let io_err = |what: &str, path: &Path, e: std::io::Error| {
        DriverError::ImageImport(format!("{what} {}: {e}", path.display()))
    };
    let file = std::fs::File::create(pseudo_file)
        .map_err(|e| io_err("failed to create pseudo file", pseudo_file, e))?;
    let mut out = std::io::BufWriter::new(file);
    let mut count = 0;
    let mut pending = vec![rootfs.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| io_err("failed to read directory", &dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err("failed to read directory", &dir, e))?;
            let path = entry.path();
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|e| io_err("failed to stat", &path, e))?;
            if metadata.is_dir() {
                pending.push(path.clone());
            }

            let relative = path.strip_prefix(rootfs).expect("walk stays inside rootfs");
            let relative = relative.as_os_str().as_bytes();
            if relative.contains(&b'\n') {
                // The pseudo file format cannot name it; it keeps the
                // unpacking user as owner.
                tracing::warn!(path = %path.display(), "cannot restore owner of a path containing a newline");
                continue;
            }
            let (uid, gid) = read_rootless_owner(&path)
                .map_err(|e| io_err("failed to read owner of", &path, e))?
                .unwrap_or((0, 0));
            let mode = metadata.mode() & 0o7777;

            out.write_all(&pseudo_quote(relative))
                .and_then(|()| writeln!(out, " m {mode:o} {uid} {gid}"))
                .map_err(|e| io_err("failed to write pseudo file", pseudo_file, e))?;
            count += 1;
        }
    }

    out.flush()
        .map_err(|e| io_err("failed to write pseudo file", pseudo_file, e))?;
    Ok(count)
}

/// Returns `reference` with any leading `docker://` scheme and any trailing
/// `:tag` and/or `@sha256:<hex>` suffix stripped, leaving just
/// `[registry-host[:port]/]path`.
pub fn repo_path(reference: &str) -> &str {
    let reference = strip_docker_scheme(reference);

    // Strip trailing @sha256:<hex>
    let without_digest = if let Some(idx) = reference.rfind("@sha256:") {
        &reference[..idx]
    } else {
        reference
    };

    // Strip trailing :tag if present in the last path segment
    if let Some(colon_idx) = without_digest.rfind(':') {
        let last_slash = without_digest.rfind('/');
        match last_slash {
            Some(slash_idx) if colon_idx > slash_idx => &without_digest[..colon_idx],
            None => &without_digest[..colon_idx],
            _ => without_digest,
        }
    } else {
        without_digest
    }
}

/// The `docker://` target `skopeo inspect` resolves `reference` through.
///
/// skopeo rejects a reference carrying both a tag and a digest ("Docker
/// references with both a tag and digest are currently not supported"), but
/// such a reference is valid and the most readable way to pin an image. The
/// digest identifies the image on its own, so the tag is dropped.
pub fn inspect_target(reference: &str) -> String {
    let bare = strip_docker_scheme(reference);
    match bare.rfind("@sha256:") {
        Some(idx) => format!("docker://{}{}", repo_path(bare), &bare[idx..]),
        None => format!("docker://{bare}"),
    }
}

/// Maps the current host architecture to the LXD architecture identifier
/// (used in an image's `metadata.yaml`).
pub fn host_lxd_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armhf",
        "s390x" => "s390x",
        "powerpc64" => "ppc64el",
        "riscv64" => "riscv64",
        other => other,
    }
}

/// Maps the current host architecture to the OCI/Go architecture identifier
/// (what `skopeo --override-arch` expects when selecting an image from a
/// multi-arch index). This differs from [`host_lxd_arch`]: e.g. LXD calls
/// amd64 `x86_64`, but OCI image indexes use `amd64`.
/// Computes a `sha256:<hex>` digest of the file's bytes at the given path.
pub fn digest_of_file(path: &Path) -> Result<String, DriverError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| {
        DriverError::ImageImport(format!(
            "failed to stat supervisor binary at {}: {e}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DriverError::ImageImport(format!(
            "supervisor binary at {} is a symlink or not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                DriverError::ImageImport(format!(
                    "failed to open supervisor binary at {}: {e}",
                    path.display()
                ))
            })?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file, &mut bytes).map_err(|e| {
            DriverError::ImageImport(format!(
                "failed to read supervisor binary at {}: {e}",
                path.display()
            ))
        })?;
        bytes
    };
    #[cfg(not(unix))]
    let bytes = std::fs::read(path).map_err(|e| {
        DriverError::ImageImport(format!(
            "failed to read supervisor binary at {}: {e}",
            path.display()
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest_hex = hex_digest(&hasher.finalize());
    Ok(format!("sha256:{digest_hex}"))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn host_oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "s390x" => "s390x",
        "powerpc64" => "ppc64le",
        "riscv64" => "riscv64",
        other => other,
    }
}

/// Trait defining the external OCI pull/convert/import capability.
#[tonic::async_trait]
pub trait OciImporter: Send + Sync {
    /// Resolves `reference` to its arch-specific manifest digest (e.g. `sha256:abcdef...`).
    async fn resolve_digest(&self, reference: &str) -> Result<String, DriverError>;

    /// Imports the image identified by `digest` and registers it in LXD under `alias`.
    async fn import(&self, reference: &str, digest: &str, alias: &str) -> Result<(), DriverError>;

    /// Extracts the supervisor binary from `reference` into `cache_dir`, returning the host binary path and image digest.
    async fn extract_supervisor_binary(
        &self,
        reference: &str,
        cache_dir: &Path,
    ) -> Result<(PathBuf, String), DriverError>;
}

/// Abstraction over checking if an image alias exists in LXD.
#[tonic::async_trait]
pub trait ImageAliasChecker: Send + Sync {
    async fn image_alias_exists(&self, alias: &str) -> Result<bool, DriverError>;
}

#[tonic::async_trait]
impl ImageAliasChecker for LxdClient {
    async fn image_alias_exists(&self, alias: &str) -> Result<bool, DriverError> {
        self.image_alias_exists(alias).await.map_err(Into::into)
    }
}

/// Image cache resolver over LXD alias lookup and an `OciImporter`.
///
/// Ensures concurrent resolutions for the same alias are serialized,
/// importing missing images at most once.
#[derive(Clone)]
pub struct ImageCache {
    alias_checker: Arc<dyn ImageAliasChecker>,
    importer: Arc<dyn OciImporter>,
    prefix: String,
    locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    supervisor_extract_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl fmt::Debug for ImageCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageCache")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl ImageCache {
    pub fn new(lxd: LxdClient, importer: Arc<dyn OciImporter>, prefix: String) -> Self {
        Self::with_checker(Arc::new(lxd), importer, prefix)
    }

    pub fn with_checker(
        alias_checker: Arc<dyn ImageAliasChecker>,
        importer: Arc<dyn OciImporter>,
        prefix: String,
    ) -> Self {
        Self {
            alias_checker,
            importer,
            prefix,
            locks: Arc::new(Mutex::new(HashMap::new())),
            supervisor_extract_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Resolves an OCI reference to a local LXD image alias.
    ///
    /// 1. Validates `reference`.
    /// 2. Resolves `reference` to its content digest (arch-specific).
    /// 3. Computes the deterministic cache alias.
    /// 4. Acquires the per-alias mutex.
    /// 5. Checks if the alias already exists in LXD (cache hit).
    /// 6. If not, calls `importer.import(reference, digest, alias)` (cache miss).
    /// 7. Returns the alias.
    pub async fn resolve_alias(&self, reference: &str) -> Result<String, DriverError> {
        validate_reference(reference)?;

        let digest = self.importer.resolve_digest(reference).await?;
        let alias = cache_alias_with_prefix(&self.prefix, &digest);

        let alias_lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(alias.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        let _guard = alias_lock.lock().await;

        if self.alias_checker.image_alias_exists(&alias).await? {
            tracing::debug!(alias = %alias, "image cache hit");
            return Ok(alias);
        }

        tracing::info!(reference = %reference, digest = %digest, alias = %alias, "image cache miss; importing");
        self.importer.import(reference, &digest, &alias).await?;
        Ok(alias)
    }

    /// Extracts the supervisor binary from `reference` into `cache_dir`, returning the host binary path and image digest.
    pub async fn extract_supervisor_binary(
        &self,
        reference: &str,
        cache_dir: &Path,
    ) -> Result<(PathBuf, String), DriverError> {
        validate_reference(reference)?;
        let digest = self.importer.resolve_digest(reference).await?;
        let clean_digest = digest.strip_prefix("sha256:").unwrap_or(&digest);
        let target_dir = cache_dir.join(clean_digest);
        let binary_path = target_dir.join("openshell-sandbox");

        let extract_lock = {
            let mut locks = self.supervisor_extract_locks.lock().await;
            locks
                .entry(digest.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        let _guard = extract_lock.lock().await;

        if is_valid_cached_binary(&binary_path).await {
            tracing::debug!(path = %binary_path.display(), "supervisor binary cache hit");
            return Ok((binary_path, digest));
        }

        self.importer
            .extract_supervisor_binary(reference, cache_dir)
            .await
    }
}

/// Validates that a cached supervisor binary exists as a regular executable
/// file owned by the current process user, rejecting symlinks.
async fn is_valid_cached_binary(path: &Path) -> bool {
    let Ok(metadata) = tokio::fs::symlink_metadata(path).await else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        tracing::warn!(path = %path.display(), "cached supervisor binary is a symlink or not a regular file; ignoring");
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            tracing::warn!(
                path = %path.display(),
                owner = metadata.uid(),
                current_uid,
                "cached supervisor binary is not owned by the driver process; ignoring"
            );
            return false;
        }
        if metadata.mode() & 0o111 == 0 {
            tracing::warn!(
                path = %path.display(),
                "cached supervisor binary is not executable; ignoring"
            );
            return false;
        }
    }
    true
}

/// Selects the host-architecture manifest digest out of a raw top-level
/// manifest document.
///
/// `raw` is the bytes `skopeo inspect --raw` returned for the reference. For a
/// multi-arch index this picks the entry matching `os`/`arch` and returns its
/// digest; for a single manifest the digest *is* the content digest of these
/// very bytes, so it is computed directly.
///
/// Split out from the subprocess call so the arch-selection rule — the part
/// that silently produced cross-architecture cache collisions when it was
/// delegated to `skopeo inspect --format {{.Digest}}` — is unit-testable.
pub fn select_arch_digest(raw: &[u8], os: &str, arch: &str) -> Result<String, DriverError> {
    let doc: serde_json::Value = serde_json::from_slice(raw).map_err(|e| {
        DriverError::ImageImport(format!("failed to parse image manifest as JSON: {e}"))
    })?;

    let Some(manifests) = doc.get("manifests").and_then(|m| m.as_array()) else {
        // Not an index: this document is itself the image manifest, so its
        // own content digest identifies it.
        let mut hasher = Sha256::new();
        hasher.update(raw);
        return Ok(format!("sha256:{}", hex_digest(&hasher.finalize())));
    };

    for entry in manifests {
        let platform = entry.get("platform");
        let entry_os = platform.and_then(|p| p.get("os")).and_then(|v| v.as_str());
        let entry_arch = platform
            .and_then(|p| p.get("architecture"))
            .and_then(|v| v.as_str());
        if entry_os == Some(os) && entry_arch == Some(arch) {
            if let Some(digest) = entry.get("digest").and_then(|d| d.as_str()) {
                return Ok(digest.to_string());
            }
        }
    }

    Err(DriverError::ImageImport(format!(
        "image index has no {os}/{arch} manifest"
    )))
}

/// Real implementation of [`OciImporter`] using `skopeo`, `umoci`, and `mksquashfs`.
pub struct SkopeoImporter {
    lxd: LxdClient,
    skopeo_path: PathBuf,
    umoci_path: PathBuf,
    mksquashfs_path: PathBuf,
    work_dir: PathBuf,
    timeout: Duration,
    arch_verified: tokio::sync::OnceCell<()>,
}

impl SkopeoImporter {
    pub fn new(
        lxd: LxdClient,
        skopeo_path: Option<PathBuf>,
        umoci_path: Option<PathBuf>,
        mksquashfs_path: Option<PathBuf>,
        work_dir: PathBuf,
        timeout: Duration,
    ) -> Self {
        Self {
            lxd,
            skopeo_path: skopeo_path.unwrap_or_else(|| PathBuf::from("skopeo")),
            umoci_path: umoci_path.unwrap_or_else(|| PathBuf::from("umoci")),
            mksquashfs_path: mksquashfs_path.unwrap_or_else(|| PathBuf::from("mksquashfs")),
            work_dir,
            timeout,
            arch_verified: tokio::sync::OnceCell::new(),
        }
    }

    async fn verify_lxd_architecture(&self) -> Result<(), DriverError> {
        self.arch_verified
            .get_or_try_init(|| async {
                self.lxd
                    .verify_architecture(host_lxd_arch())
                    .await
                    .map_err(|e| match e {
                        lxd_client::LxdError::Api { message, .. } => {
                            DriverError::ImageImport(message)
                        }
                        other => DriverError::ImageImport(format!(
                            "failed to verify LXD server architecture: {other}"
                        )),
                    })
            })
            .await
            .map(|_| ())
    }

    /// Creates the scratch directory for one conversion inside the configured
    /// work dir, rather than `TMPDIR`/`/tmp`, which is a small tmpfs on most
    /// modern distributions and cannot hold an unpacked sandbox rootfs.
    fn scratch_dir(&self, prefix: &str) -> Result<tempfile::TempDir, DriverError> {
        std::fs::create_dir_all(&self.work_dir).map_err(|e| {
            DriverError::ImageImport(format!(
                "failed to create image work directory {}: {e}",
                self.work_dir.display()
            ))
        })?;
        tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(&self.work_dir)
            .map_err(|e| {
                DriverError::ImageImport(format!(
                    "failed to create scratch directory in {}: {e}",
                    self.work_dir.display()
                ))
            })
    }
}

#[tonic::async_trait]
impl OciImporter for SkopeoImporter {
    async fn resolve_digest(&self, reference: &str) -> Result<String, DriverError> {
        self.verify_lxd_architecture().await?;
        let target = inspect_target(reference);

        // `--raw` returns the top-level manifest document untouched. Two
        // reasons to prefer it over `inspect --format {{.Digest}}`:
        //
        //  * `{{.Digest}}` reports the digest of the *index* even under
        //    `--override-arch`, so every architecture resolved to the same
        //    digest and shared one cache alias.
        //  * a plain `inspect` also paginates the repository's whole tag
        //    list, which costs ~13s on a repo with thousands of tags and is
        //    pure waste when only the digest is wanted.
        let cmd = tokio::process::Command::new(&self.skopeo_path)
            .args(["inspect", "--raw", &target])
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, cmd)
            .await
            .map_err(|_| {
                DriverError::ImageImport(format!("skopeo inspect timed out for {reference:?}"))
            })?
            .map_err(|e| DriverError::ImageImport(format!("failed to execute skopeo: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriverError::ImageImport(format!(
                "skopeo inspect failed for {reference:?}: {stderr}"
            )));
        }

        select_arch_digest(&output.stdout, "linux", host_oci_arch()).map_err(|e| {
            DriverError::ImageImport(format!("failed to resolve digest for {reference:?}: {e}"))
        })
    }

    async fn import(&self, reference: &str, digest: &str, alias: &str) -> Result<(), DriverError> {
        self.verify_lxd_architecture().await?;
        let oci_arch = host_oci_arch();
        let lxd_arch = host_lxd_arch();
        let repo = repo_path(reference);
        let copy_source = format!("docker://{repo}@{digest}");

        // Create scratch directory for conversion, on disk rather than tmpfs.
        let temp_dir = self.scratch_dir("openshell-oci-import-")?;
        let temp_path = temp_dir.path();

        let oci_dest = temp_path.join("oci");
        let bundle_dest = temp_path.join("bundle");
        let rootfs_dest = bundle_dest.join("rootfs");
        let squashfs_path = temp_path.join("rootfs.squashfs");

        // 1. skopeo copy docker://<repo>@<digest> oci:<temp_path>/oci:img
        let oci_tag_arg = format!("oci:{}:img", oci_dest.display());
        let cmd = tokio::process::Command::new(&self.skopeo_path)
            .args([
                "copy",
                "--override-os",
                "linux",
                "--override-arch",
                oci_arch,
                &copy_source,
                &oci_tag_arg,
            ])
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, cmd)
            .await
            .map_err(|_| {
                DriverError::ImageImport(format!("skopeo copy timed out for {copy_source:?}"))
            })?
            .map_err(|e| DriverError::ImageImport(format!("failed to execute skopeo copy: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriverError::ImageImport(format!(
                "skopeo copy failed for {copy_source:?}: {stderr}"
            )));
        }

        // 2. umoci unpack --image <temp_path>/oci:img <temp_path>/bundle
        let cmd = tokio::process::Command::new(&self.umoci_path)
            .args([
                "unpack",
                "--rootless",
                "--image",
                &format!("{}:img", oci_dest.display()),
                &bundle_dest.display().to_string(),
            ])
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, cmd)
            .await
            .map_err(|_| DriverError::ImageImport(format!("umoci unpack timed out for {alias}")))?
            .map_err(|e| {
                DriverError::ImageImport(format!("failed to execute umoci unpack: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriverError::ImageImport(format!(
                "umoci unpack failed for {alias}: {stderr}"
            )));
        }

        // The compressed OCI copy has served its purpose now that the rootfs
        // is unpacked. Dropping it here keeps peak scratch usage to the
        // rootfs plus the squashfs being written, instead of holding all
        // three representations of the image at once.
        if let Err(e) = tokio::fs::remove_dir_all(&oci_dest).await {
            tracing::debug!(path = %oci_dest.display(), %e, "could not free OCI copy early");
        }

        // Inject the minimal init script before repacking with mksquashfs, and
        // make it the container's init.
        inject_init_script(&rootfs_dest)?;
        install_init(&rootfs_dest)?;

        // Restore the owners the image specifies, which the rootless unpack
        // only recorded in xattrs.
        let pseudo_path = temp_path.join("ownership.pseudo");
        let entries = {
            let rootfs = rootfs_dest.clone();
            let pseudo = pseudo_path.clone();
            tokio::task::spawn_blocking(move || write_ownership_pseudo_file(&rootfs, &pseudo))
                .await
                .map_err(|e| DriverError::ImageImport(format!("ownership scan panicked: {e}")))??
        };
        tracing::debug!(alias = %alias, entries, "restoring image file ownership");

        // 3. mksquashfs <rootfs_dest> <squashfs_path>, with the image's
        //    ownership applied and umoci's bookkeeping xattr left out.
        let cmd = tokio::process::Command::new(&self.mksquashfs_path)
            .args([
                rootfs_dest.as_os_str(),
                squashfs_path.as_os_str(),
                std::ffi::OsStr::new("-noappend"),
                std::ffi::OsStr::new("-root-uid"),
                std::ffi::OsStr::new("0"),
                std::ffi::OsStr::new("-root-gid"),
                std::ffi::OsStr::new("0"),
                std::ffi::OsStr::new("-pf"),
                pseudo_path.as_os_str(),
                std::ffi::OsStr::new("-xattrs-exclude"),
                std::ffi::OsStr::new("^user\\.rootlesscontainers$"),
            ])
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, cmd)
            .await
            .map_err(|_| DriverError::ImageImport(format!("mksquashfs timed out for {alias}")))?
            .map_err(|e| DriverError::ImageImport(format!("failed to execute mksquashfs: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriverError::ImageImport(format!(
                "mksquashfs failed for {alias}: {stderr}"
            )));
        }

        // 4. Assemble metadata.tar.xz
        // metadata.yaml contains architecture and creation date
        let creation_date = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let metadata_yaml = format!(
            "architecture: \"{lxd_arch}\"\ncreation_date: {creation_date}\nproperties:\n  description: \"OpenShell sandbox {alias}\"\n"
        );

        let metadata_tar_bytes = create_metadata_tar_xz(temp_path, &metadata_yaml).await?;

        // 5. Upload via LxdClient::create_image_from_split + wait_operation
        let op = tokio::time::timeout(
            self.timeout,
            self.lxd.create_image_from_split(
                "metadata.tar.xz",
                &metadata_tar_bytes,
                "rootfs.squashfs",
                &squashfs_path,
            ),
        )
        .await
        .map_err(|_| DriverError::ImageImport("timed out uploading split image to LXD".into()))?
        .map_err(|e| DriverError::ImageImport(format!("LXD split image upload failed: {e}")))?;

        let finished_op = tokio::time::timeout(self.timeout, self.lxd.wait_operation(&op.id))
            .await
            .map_err(|_| {
                DriverError::ImageImport("timed out waiting for image upload operation".into())
            })?
            .map_err(|e| DriverError::ImageImport(format!("image upload operation failed: {e}")))?;

        let fingerprint = finished_op
            .metadata
            .as_ref()
            .and_then(|m| m.get("fingerprint"))
            .and_then(|f| f.as_str())
            .ok_or_else(|| {
                DriverError::ImageImport("operation response missing image fingerprint".into())
            })?;

        // 6. Bind the alias to the fingerprint
        if let Err(e) = self
            .lxd
            .create_image_alias(
                alias,
                fingerprint,
                Some(&format!("OpenShell image {digest}")),
            )
            .await
        {
            if let Ok(aliases) = self.lxd.get_image_aliases(fingerprint).await {
                if aliases.is_empty() {
                    if let Ok(del_op) = self.lxd.delete_image(fingerprint).await {
                        let _ =
                            tokio::time::timeout(self.timeout, self.lxd.wait_operation(&del_op.id))
                                .await;
                    }
                }
            }
            return Err(DriverError::ImageImport(format!(
                "failed to create image alias {alias}: {e}"
            )));
        }

        Ok(())
    }

    async fn extract_supervisor_binary(
        &self,
        reference: &str,
        cache_dir: &Path,
    ) -> Result<(PathBuf, String), DriverError> {
        self.verify_lxd_architecture().await?;
        validate_reference(reference)?;
        let digest = self.resolve_digest(reference).await?;
        let clean_digest = digest.strip_prefix("sha256:").unwrap_or(&digest);
        let target_dir = cache_dir.join(clean_digest);
        let binary_path = target_dir.join("openshell-sandbox");

        if binary_path.exists() {
            tracing::debug!(path = %binary_path.display(), "supervisor binary cache hit");
            return Ok((binary_path, digest));
        }

        tracing::info!(
            reference = %reference,
            digest = %digest,
            "supervisor binary cache miss; extracting"
        );

        let oci_arch = host_oci_arch();
        let repo = repo_path(reference);
        let copy_source = format!("docker://{repo}@{digest}");

        let temp_dir = self.scratch_dir("openshell-supervisor-extract-")?;
        let temp_path = temp_dir.path();

        let oci_dest = temp_path.join("oci");
        let bundle_dest = temp_path.join("bundle");
        let rootfs_dest = bundle_dest.join("rootfs");

        // 1. skopeo copy docker://<repo>@<digest> oci:<temp_path>/oci:img
        let oci_tag_arg = format!("oci:{}:img", oci_dest.display());
        let cmd = tokio::process::Command::new(&self.skopeo_path)
            .args([
                "copy",
                "--override-os",
                "linux",
                "--override-arch",
                oci_arch,
                &copy_source,
                &oci_tag_arg,
            ])
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, cmd)
            .await
            .map_err(|_| {
                DriverError::ImageImport(format!("skopeo copy timed out for {copy_source:?}"))
            })?
            .map_err(|e| DriverError::ImageImport(format!("failed to execute skopeo copy: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriverError::ImageImport(format!(
                "skopeo copy failed for {copy_source:?}: {stderr}"
            )));
        }

        // 2. umoci unpack --image <temp_path>/oci:img <temp_path>/bundle
        let cmd = tokio::process::Command::new(&self.umoci_path)
            .args([
                "unpack",
                "--rootless",
                "--image",
                &format!("{}:img", oci_dest.display()),
                &bundle_dest.display().to_string(),
            ])
            .kill_on_drop(true)
            .output();

        let output = tokio::time::timeout(self.timeout, cmd)
            .await
            .map_err(|_| {
                DriverError::ImageImport(format!("umoci unpack timed out for {reference}"))
            })?
            .map_err(|e| {
                DriverError::ImageImport(format!("failed to execute umoci unpack: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DriverError::ImageImport(format!(
                "umoci unpack failed for {reference}: {stderr}"
            )));
        }

        let extracted_source = rootfs_dest.join("openshell-sandbox");

        tokio::fs::create_dir_all(&target_dir).await.map_err(|e| {
            DriverError::ImageImport(format!(
                "failed to create supervisor cache directory {}: {e}",
                target_dir.display()
            ))
        })?;

        // Unique per call, not just per process: two concurrent creates in
        // this process extracting the same digest would otherwise race on one
        // staging path and one of them would rename a half-written file.
        static EXTRACT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let temp_target = target_dir.join(format!(
            ".openshell-sandbox.tmp.{}.{}",
            std::process::id(),
            EXTRACT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));

        copy_extracted_binary(&extracted_source, &temp_target, reference).await?;

        if is_valid_cached_binary(&binary_path).await {
            let _ = tokio::fs::remove_file(&temp_target).await;
            tracing::debug!(path = %binary_path.display(), "supervisor binary already committed; treating as cache hit");
            return Ok((binary_path, digest));
        }

        if let Err(e) = tokio::fs::rename(&temp_target, &binary_path).await {
            if is_valid_cached_binary(&binary_path).await {
                let _ = tokio::fs::remove_file(&temp_target).await;
                tracing::debug!(path = %binary_path.display(), "supervisor binary already committed by another extractor; treating as cache hit");
                return Ok((binary_path, digest));
            }
            return Err(DriverError::ImageImport(format!(
                "failed to commit extracted supervisor binary to {}: {e}",
                binary_path.display()
            )));
        }

        Ok((binary_path, digest))
    }
}

/// Copies an extracted supervisor binary to its destination.
///
/// Requires that the source is a regular file (rejecting symlinks) and copies
/// it without following symlinks so an image cannot point at a host file.
async fn copy_extracted_binary(
    source: &Path,
    target: &Path,
    reference: &str,
) -> Result<(), DriverError> {
    let metadata = match tokio::fs::symlink_metadata(source).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DriverError::ImageImport(format!(
                "image {reference:?} does not contain /openshell-sandbox"
            )));
        }
        Err(e) => {
            return Err(DriverError::ImageImport(format!(
                "failed to stat /openshell-sandbox in image {reference:?}: {e}"
            )));
        }
    };

    if metadata.file_type().is_symlink() {
        return Err(DriverError::ImageImport(format!(
            "image {reference:?} has a symlink at /openshell-sandbox"
        )));
    }
    if !metadata.is_file() {
        return Err(DriverError::ImageImport(format!(
            "image {reference:?} does not contain a regular file at /openshell-sandbox"
        )));
    }

    #[cfg(unix)]
    {
        let mut source_file = tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)
            .await
            .map_err(|e| {
                DriverError::ImageImport(format!(
                    "failed to open extracted supervisor binary {}: {e}",
                    source.display()
                ))
            })?;
        let mut target_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(target)
            .await
            .map_err(|e| {
                DriverError::ImageImport(format!(
                    "failed to create temporary supervisor binary {}: {e}",
                    target.display()
                ))
            })?;
        tokio::io::copy(&mut source_file, &mut target_file)
            .await
            .map_err(|e| {
                DriverError::ImageImport(format!(
                    "failed to copy extracted supervisor binary to {}: {e}",
                    target.display()
                ))
            })?;

        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755)).await;
    }

    #[cfg(not(unix))]
    {
        tokio::fs::copy(source, target).await.map_err(|e| {
            DriverError::ImageImport(format!(
                "failed to copy extracted supervisor binary to {}: {e}",
                target.display()
            ))
        })?;
    }

    Ok(())
}

/// Creates a `.tar.xz` archive containing `metadata.yaml` in the given directory.
async fn create_metadata_tar_xz(dir: &Path, metadata_yaml: &str) -> Result<Vec<u8>, DriverError> {
    let metadata_path = dir.join("metadata.yaml");
    let tar_path = dir.join("metadata.tar.xz");

    tokio::fs::write(&metadata_path, metadata_yaml.as_bytes())
        .await
        .map_err(|e| DriverError::ImageImport(format!("failed to write metadata.yaml: {e}")))?;

    let output = tokio::process::Command::new("tar")
        .arg("-cJf")
        .arg(&tar_path)
        .arg("-C")
        .arg(dir)
        .arg("metadata.yaml")
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| DriverError::ImageImport(format!("failed to run tar for metadata: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DriverError::ImageImport(format!(
            "failed to build metadata.tar.xz: {stderr}"
        )));
    }

    tokio::fs::read(&tar_path)
        .await
        .map_err(|e| DriverError::ImageImport(format!("failed to read metadata.tar.xz: {e}")))
}

/// Injects the bundled init script into the unpacked rootfs at `GUEST_INIT_SCRIPT_PATH`
/// with executable permissions (`0755`).
fn inject_init_script(rootfs_dest: &Path) -> Result<(), DriverError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // The script sits at the top of the rootfs, so the only path component
    // an image controls is the file itself. An image may ship that path as a
    // symlink (say to /etc/shadow): writing through it would let the image
    // overwrite a host file as the driver's user. Whatever is there is
    // removed without being followed, and the script is created fresh.
    let script_path = rootfs_dest.join(GUEST_INIT_SCRIPT_PATH.trim_start_matches('/'));
    match std::fs::symlink_metadata(&script_path) {
        Ok(metadata) if metadata.is_dir() => {
            return Err(DriverError::ImageImport(format!(
                "the image has a directory at {GUEST_INIT_SCRIPT_PATH}"
            )));
        }
        Ok(_) => std::fs::remove_file(&script_path).map_err(|e| {
            DriverError::ImageImport(format!(
                "failed to remove {} from the image: {e}",
                script_path.display()
            ))
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(DriverError::ImageImport(format!(
                "failed to stat {}: {e}",
                script_path.display()
            )))
        }
    }

    // `create_new` refuses to open anything that appeared in between,
    // symlinks included.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&script_path)
        .and_then(|mut file| file.write_all(INIT_SCRIPT_CONTENTS.as_bytes()))
        .map_err(|e| {
            DriverError::ImageImport(format!(
                "failed to write init script to {}: {e}",
                script_path.display()
            ))
        })
}

/// Resolves `guest_path`, an absolute path as the container sees it, to the
/// host path it names under `rootfs`, following symlinks in its directories
/// the way the container would.
///
/// The rootfs comes from an arbitrary image, so its symlinks must never be
/// followed on the host: `sbin -> /usr/sbin` would otherwise lead the driver
/// to the host's own `/usr/sbin`. Absolute targets are taken relative to
/// `rootfs` and `..` stops at it. The last component is not followed.
fn resolve_in_rootfs(rootfs: &Path, guest_path: &str) -> Result<PathBuf, DriverError> {
    use std::collections::VecDeque;
    use std::path::Component;

    let guest = Path::new(guest_path);
    let file_name = guest
        .file_name()
        .ok_or_else(|| DriverError::ImageImport(format!("{guest_path:?} does not name a file")))?;
    let mut pending: VecDeque<_> = guest
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .map(|c| c.as_os_str().to_owned())
        .collect();

    let mut resolved = PathBuf::new();
    let mut hops = 0;
    while let Some(part) = pending.pop_front() {
        match Path::new(&part).components().next() {
            Some(Component::Normal(name)) => {
                let candidate = rootfs.join(&resolved).join(name);
                let is_symlink = std::fs::symlink_metadata(&candidate)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink());
                if !is_symlink {
                    resolved.push(name);
                    continue;
                }
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(DriverError::ImageImport(format!(
                        "too many symlinks resolving {guest_path:?} in the image"
                    )));
                }
                let target = std::fs::read_link(&candidate).map_err(|e| {
                    DriverError::ImageImport(format!(
                        "failed to read symlink {}: {e}",
                        candidate.display()
                    ))
                })?;
                if target.is_absolute() {
                    resolved.clear();
                }
                for component in target.components().rev() {
                    pending.push_front(component.as_os_str().to_owned());
                }
            }
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            // The root and `.` leave the position unchanged.
            _ => {}
        }
    }

    Ok(rootfs.join(resolved).join(file_name))
}

/// Makes [`GUEST_INIT_PATH`] a symlink to the injected init script, replacing
/// whatever init the image shipped: a sandbox's init is always the script,
/// which hands over to the supervisor.
fn install_init(rootfs_dest: &Path) -> Result<(), DriverError> {
    let init = resolve_in_rootfs(rootfs_dest, GUEST_INIT_PATH)?;
    let io_err = |what: &str, e: std::io::Error| {
        DriverError::ImageImport(format!("failed to {what} {}: {e}", init.display()))
    };

    if let Some(parent) = init.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err("create the parent of", e))?;
    }
    match std::fs::symlink_metadata(&init) {
        Ok(metadata) if metadata.is_dir() => {
            return Err(DriverError::ImageImport(format!(
                "the image has a directory at {GUEST_INIT_PATH}"
            )));
        }
        Ok(_) => std::fs::remove_file(&init).map_err(|e| io_err("remove", e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err("stat", e)),
    }
    std::os::unix::fs::symlink(GUEST_INIT_SCRIPT_PATH, &init).map_err(|e| io_err("create", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_alias_golden() {
        let digest_body = "ab".repeat(32);
        let digest = format!("sha256:{digest_body}");
        let alias = cache_alias(&digest);
        assert_eq!(alias, format!("openshell-oci-r3-{digest_body}"));
        assert_eq!(alias.len(), "openshell-oci-r3-".len() + 64);
    }

    /// Values observed from `umoci unpack --rootless` (umoci 0.4.7).
    #[test]
    fn rootless_owner_records_decode() {
        // uid 998, gid 998
        assert_eq!(
            decode_rootless_owner(&[0x08, 0xe6, 0x07, 0x10, 0xe6, 0x07]),
            Some((998, 998))
        );
        // uid unchanged (root), gid 42
        assert_eq!(
            decode_rootless_owner(&[0x08, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x10, 0x2a]),
            Some((0, 42))
        );
        assert_eq!(decode_rootless_owner(&[]), Some((0, 0)));
        // Truncated varint and a non-varint field are rejected.
        assert_eq!(decode_rootless_owner(&[0x08, 0xe6]), None);
        assert_eq!(decode_rootless_owner(&[0x0a, 0x01]), None);
    }

    #[test]
    fn pseudo_paths_are_quoted() {
        assert_eq!(pseudo_quote(b"etc/passwd"), b"\"etc/passwd\"".to_vec());
        assert_eq!(
            pseudo_quote(br#"dir with space/fi"le\x"#),
            br#""dir with space/fi\"le\\x""#.to_vec()
        );
    }

    #[cfg(target_os = "linux")]
    fn set_rootless_owner(path: &Path, value: &[u8]) -> bool {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let c_name = CString::new(ROOTLESS_OWNER_XATTR).unwrap();
        // SAFETY: NUL-terminated strings and a correctly sized value.
        unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            ) == 0
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ownership_pseudo_file_restores_recorded_owners() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("sandbox")).unwrap();
        std::fs::write(rootfs.join("sandbox/.bashrc"), b"x").unwrap();
        std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        std::fs::write(rootfs.join("usr/bin/sudo"), b"x").unwrap();
        for (path, mode) in [
            ("sandbox", 0o755),
            ("sandbox/.bashrc", 0o644),
            ("usr", 0o755),
            ("usr/bin", 0o755),
            ("usr/bin/sudo", 0o4755),
        ] {
            std::fs::set_permissions(rootfs.join(path), std::fs::Permissions::from_mode(mode))
                .unwrap();
        }
        std::os::unix::fs::symlink("sandbox/.bashrc", rootfs.join("link")).unwrap();

        let owner_998 = [0x08, 0xe6, 0x07, 0x10, 0xe6, 0x07];
        if !set_rootless_owner(&rootfs.join("sandbox"), &owner_998) {
            eprintln!("user xattrs unsupported here; skipping");
            return;
        }
        assert!(set_rootless_owner(
            &rootfs.join("sandbox/.bashrc"),
            &owner_998
        ));

        let pseudo = temp.path().join("ownership.pseudo");
        let count = write_ownership_pseudo_file(&rootfs, &pseudo).unwrap();
        let contents = std::fs::read_to_string(&pseudo).unwrap();
        let mut lines: Vec<&str> = contents.lines().collect();
        lines.sort_unstable();

        assert_eq!(count, 6, "{contents}");
        assert_eq!(
            lines,
            vec![
                "\"link\" m 777 0 0",
                "\"sandbox\" m 755 998 998",
                "\"sandbox/.bashrc\" m 644 998 998",
                "\"usr\" m 755 0 0",
                "\"usr/bin\" m 755 0 0",
                "\"usr/bin/sudo\" m 4755 0 0",
            ]
        );
    }

    #[test]
    fn cache_alias_uniqueness() {
        let d1 = format!("sha256:{}", "01".repeat(32));
        let d2 = format!("sha256:{}", "02".repeat(32));
        assert_ne!(cache_alias(&d1), cache_alias(&d2));
    }

    #[test]
    fn reference_validation() {
        // Valid references
        assert!(validate_reference("ubuntu").is_ok());
        assert!(validate_reference("ubuntu:22.04").is_ok());
        assert!(validate_reference("registry.example.com/openshell-sandbox:test").is_ok());
        assert!(validate_reference("registry.example.com:5000/repo/app:v1.0").is_ok());
        let full_digest = format!("registry.example.com/app@sha256:{}", "ab".repeat(32));
        assert!(validate_reference(&full_digest).is_ok());
        let tagged_and_digested = format!("registry.example.com/app:v1@sha256:{}", "ab".repeat(32));
        assert!(validate_reference(&tagged_and_digested).is_ok());
        // Optional docker:// transport prefix is accepted.
        assert!(validate_reference("docker://ubuntu:22.04").is_ok());
        assert!(validate_reference("docker://registry.example.com/org/sandbox:latest").is_ok());

        // Invalid references (shell injection / malformed) are the caller's
        // mistake.
        for invalid in [
            "",
            "ubuntu; rm -rf /",
            "ubuntu && touch /tmp/pwn",
            "ubuntu|cat",
            "ubuntu`id`",
            "ubuntu$(id)",
            "ubuntu\n",
            "ubuntu foo",
            "ubuntu:",
            "UPPER/Case::bad",
        ] {
            assert!(
                matches!(
                    validate_reference(invalid),
                    Err(DriverError::InvalidArgument(_))
                ),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn inspect_target_drops_the_tag_of_a_pinned_reference() {
        let digest = format!("sha256:{}", "ab".repeat(32));
        let cases = [
            (
                format!("ghcr.io/nvidia/openshell/supervisor:0.0.116@{digest}"),
                format!("docker://ghcr.io/nvidia/openshell/supervisor@{digest}"),
            ),
            (
                format!("docker://registry.example.com:5000/app:v1@{digest}"),
                format!("docker://registry.example.com:5000/app@{digest}"),
            ),
            (
                format!("registry.example.com/app@{digest}"),
                format!("docker://registry.example.com/app@{digest}"),
            ),
            (
                "registry.example.com:5000/app:v1".to_string(),
                "docker://registry.example.com:5000/app:v1".to_string(),
            ),
            ("docker://ubuntu".to_string(), "docker://ubuntu".to_string()),
        ];
        for (reference, expected) in cases {
            assert_eq!(inspect_target(&reference), expected, "{reference}");
        }
    }

    #[test]
    fn repo_extraction() {
        let digest_hex = "ab".repeat(32);
        assert_eq!(repo_path("ubuntu"), "ubuntu");
        assert_eq!(repo_path("ubuntu:22.04"), "ubuntu");
        assert_eq!(
            repo_path("registry.example.com:5000/app:latest"),
            "registry.example.com:5000/app"
        );
        assert_eq!(
            repo_path(&format!("registry.example.com/foo@sha256:{digest_hex}")),
            "registry.example.com/foo"
        );
        assert_eq!(
            repo_path(&format!(
                "registry.example.com:5000/foo:v1@sha256:{digest_hex}"
            )),
            "registry.example.com:5000/foo"
        );
        // docker:// scheme is stripped along with tag/digest suffixes.
        assert_eq!(
            repo_path("docker://registry.example.com/org/sandbox:latest"),
            "registry.example.com/org/sandbox"
        );
        assert_eq!(
            repo_path(&format!(
                "docker://registry.example.com/org/sandbox@sha256:{digest_hex}"
            )),
            "registry.example.com/org/sandbox"
        );
    }

    /// A multi-arch index must resolve to a *different* digest per
    /// architecture. Regression guard: `skopeo inspect --format {{.Digest}}`
    /// returns the index digest even under `--override-arch`, so amd64 and
    /// arm64 both mapped to one cache alias and one host could serve another
    /// architecture's image out of the cache.
    #[test]
    fn arch_digest_differs_per_architecture() {
        let index = br#"{
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:aaaa", "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "sha256:bbbb", "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": "sha256:cccc", "platform": {"os": "unknown", "architecture": "unknown"}}
            ]
        }"#;

        let amd = select_arch_digest(index, "linux", "amd64").unwrap();
        let arm = select_arch_digest(index, "linux", "arm64").unwrap();
        assert_eq!(amd, "sha256:aaaa");
        assert_eq!(arm, "sha256:bbbb");
        assert_ne!(amd, arm);

        // An architecture the index does not carry is an error, not a
        // silent fallback to some other arch's manifest.
        assert!(select_arch_digest(index, "linux", "riscv64").is_err());
    }

    #[test]
    fn single_manifest_digest_is_content_digest() {
        // Not an index: the digest is the sha256 of the document itself.
        let raw = br#"{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}"#;
        let digest = select_arch_digest(raw, "linux", "amd64").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(raw);
        assert_eq!(digest, format!("sha256:{}", hex_digest(&hasher.finalize())));
    }

    #[test]
    fn malformed_manifest_is_rejected() {
        assert!(select_arch_digest(b"not json", "linux", "amd64").is_err());
    }

    #[test]
    fn host_lxd_arch_is_valid() {
        let arch = host_lxd_arch();
        assert!(!arch.is_empty());
    }

    #[test]
    fn host_oci_arch_uses_oci_names() {
        // skopeo selects from a multi-arch index using OCI/Go arch names, not
        // LXD's (e.g. amd64, not x86_64), so the two must not be conflated.
        let arch = host_oci_arch();
        assert!(!arch.is_empty());
        assert_ne!(arch, "x86_64");
        assert_ne!(arch, "aarch64");
    }

    struct MockImporter {
        digest_to_return: String,
        import_calls: std::sync::atomic::AtomicUsize,
        extract_calls: std::sync::atomic::AtomicUsize,
        recorded_repo_digest: std::sync::Mutex<Vec<(String, String)>>,
        import_delay: Duration,
    }

    #[tonic::async_trait]
    impl OciImporter for MockImporter {
        async fn resolve_digest(&self, _reference: &str) -> Result<String, DriverError> {
            Ok(self.digest_to_return.clone())
        }

        async fn import(
            &self,
            reference: &str,
            digest: &str,
            _alias: &str,
        ) -> Result<(), DriverError> {
            self.import_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.recorded_repo_digest
                .lock()
                .unwrap()
                .push((reference.to_string(), digest.to_string()));
            if !self.import_delay.is_zero() {
                tokio::time::sleep(self.import_delay).await;
            }
            Ok(())
        }

        async fn extract_supervisor_binary(
            &self,
            _reference: &str,
            cache_dir: &Path,
        ) -> Result<(PathBuf, String), DriverError> {
            self.extract_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let clean = self
                .digest_to_return
                .strip_prefix("sha256:")
                .unwrap_or(&self.digest_to_return);
            let target_dir = cache_dir.join(clean);
            let binary_path = target_dir.join("openshell-sandbox");
            if binary_path.exists() {
                return Ok((binary_path, self.digest_to_return.clone()));
            }
            std::fs::create_dir_all(&target_dir).map_err(|e| {
                DriverError::ImageImport(format!("failed to create cache dir: {e}"))
            })?;
            std::fs::write(&binary_path, b"mock-supervisor-binary").map_err(|e| {
                DriverError::ImageImport(format!("failed to write mock binary: {e}"))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&binary_path, std::fs::Permissions::from_mode(0o755));
            }
            Ok((binary_path, self.digest_to_return.clone()))
        }
    }

    struct MockAliasChecker {
        existing_aliases: std::sync::Mutex<std::collections::HashSet<String>>,
    }

    #[tonic::async_trait]
    impl ImageAliasChecker for MockAliasChecker {
        async fn image_alias_exists(&self, alias: &str) -> Result<bool, DriverError> {
            Ok(self.existing_aliases.lock().unwrap().contains(alias))
        }
    }

    #[tokio::test]
    async fn cache_hit_and_miss_and_concurrency() {
        let digest_hex = "cc".repeat(32);
        let digest = format!("sha256:{digest_hex}");
        let importer = Arc::new(MockImporter {
            digest_to_return: digest.clone(),
            import_calls: std::sync::atomic::AtomicUsize::new(0),
            extract_calls: std::sync::atomic::AtomicUsize::new(0),
            recorded_repo_digest: std::sync::Mutex::new(Vec::new()),
            import_delay: Duration::from_millis(50),
        });

        let alias_checker = Arc::new(MockAliasChecker {
            existing_aliases: std::sync::Mutex::new(std::collections::HashSet::new()),
        });

        let prefix = "test-oci-".to_string();
        let cache =
            ImageCache::with_checker(alias_checker.clone(), importer.clone(), prefix.clone());

        // 1. Initial resolution is a miss -> calls importer.import once
        let res_alias = cache.resolve_alias("ubuntu:22.04").await.unwrap();
        let expected_alias = format!("test-oci-r3-{digest_hex}");
        assert_eq!(res_alias, expected_alias);
        assert_eq!(
            importer
                .import_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // Mark alias as now existing in LXD
        alias_checker
            .existing_aliases
            .lock()
            .unwrap()
            .insert(expected_alias.clone());

        // 2. Second resolution is a hit -> does not call importer.import again
        let res_alias2 = cache.resolve_alias("ubuntu:22.04").await.unwrap();
        assert_eq!(res_alias2, expected_alias);
        assert_eq!(
            importer
                .import_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // 3. Concurrency guard test: clear existing aliases, launch 5 concurrent resolves
        alias_checker.existing_aliases.lock().unwrap().clear();
        importer
            .import_calls
            .store(0, std::sync::atomic::Ordering::SeqCst);

        // A custom mock alias checker that sets the alias upon import
        struct AutoImportingImporter {
            inner: Arc<MockImporter>,
            checker: Arc<MockAliasChecker>,
        }

        #[tonic::async_trait]
        impl OciImporter for AutoImportingImporter {
            async fn resolve_digest(&self, ref_str: &str) -> Result<String, DriverError> {
                self.inner.resolve_digest(ref_str).await
            }

            async fn import(
                &self,
                reference: &str,
                digest: &str,
                alias: &str,
            ) -> Result<(), DriverError> {
                self.inner.import(reference, digest, alias).await?;
                self.checker
                    .existing_aliases
                    .lock()
                    .unwrap()
                    .insert(alias.to_string());
                Ok(())
            }

            async fn extract_supervisor_binary(
                &self,
                reference: &str,
                cache_dir: &Path,
            ) -> Result<(PathBuf, String), DriverError> {
                self.inner
                    .extract_supervisor_binary(reference, cache_dir)
                    .await
            }
        }

        let auto_importer = Arc::new(AutoImportingImporter {
            inner: importer.clone(),
            checker: alias_checker.clone(),
        });

        let cache = Arc::new(ImageCache::with_checker(
            alias_checker.clone(),
            auto_importer,
            prefix,
        ));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let cache_clone = cache.clone();
            handles.push(tokio::spawn(async move {
                cache_clone.resolve_alias("ubuntu:22.04").await
            }));
        }

        for handle in handles {
            let res = handle.await.unwrap().unwrap();
            assert_eq!(res, expected_alias);
        }

        // Exactly 1 import call occurred among the 5 concurrent requests
        assert_eq!(
            importer
                .import_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[test]
    fn digest_import_consistency() {
        // Assert that the copy target uses the resolved digest rather than original tag
        let ref_with_tag = "registry.example.com/org/app:v1.2.3";
        let resolved_digest = format!("sha256:{}", "ff".repeat(32));
        let repo = repo_path(ref_with_tag);
        assert_eq!(repo, "registry.example.com/org/app");
        let copy_source = format!("docker://{repo}@{resolved_digest}");
        assert_eq!(
            copy_source,
            format!(
                "docker://registry.example.com/org/app@sha256:{}",
                "ff".repeat(32)
            )
        );

        // A user-supplied docker:// scheme must not produce a doubled scheme.
        let ref_with_scheme = "docker://registry.example.com/org/app:v1.2.3";
        let repo_with_scheme = repo_path(ref_with_scheme);
        assert_eq!(repo_with_scheme, "registry.example.com/org/app");
        let copy_source_with_scheme = format!("docker://{repo_with_scheme}@{resolved_digest}");
        assert_eq!(copy_source_with_scheme, copy_source);
    }

    #[test]
    fn test_inject_init_script() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        inject_init_script(&rootfs).unwrap();

        let expected_path = rootfs.join(GUEST_INIT_SCRIPT_PATH.trim_start_matches('/'));
        assert!(expected_path.exists());
        let contents = std::fs::read_to_string(&expected_path).unwrap();
        assert!(!contents.is_empty());
        assert_eq!(contents, INIT_SCRIPT_CONTENTS);

        #[cfg(unix)]
        {
            let metadata = std::fs::metadata(&expected_path).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }
    }

    /// An image that ships the script's path as a symlink must not get the
    /// driver to write through it.
    #[test]
    fn init_script_is_not_written_through_a_symlink_in_the_image() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        let host_file = temp_dir.path().join("host-secret");
        std::fs::write(&host_file, "do not touch").unwrap();
        std::fs::set_permissions(&host_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&host_file, rootfs.join("openshell-init.sh")).unwrap();

        inject_init_script(&rootfs).unwrap();

        assert_eq!(std::fs::read_to_string(&host_file).unwrap(), "do not touch");
        let host_mode = std::fs::metadata(&host_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(host_mode, 0o600);
        let script = rootfs.join("openshell-init.sh");
        assert!(!std::fs::symlink_metadata(&script)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(&script).unwrap(),
            INIT_SCRIPT_CONTENTS
        );
    }

    #[test]
    fn init_is_the_init_script() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("sbin")).unwrap();
        std::fs::write(rootfs.join("sbin/init"), "#!/bin/sh\nexec systemd\n").unwrap();

        install_init(&rootfs).unwrap();

        let init = rootfs.join("sbin/init");
        assert!(std::fs::symlink_metadata(&init)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_link(&init).unwrap(),
            PathBuf::from(GUEST_INIT_SCRIPT_PATH)
        );
    }

    #[test]
    fn init_is_installed_where_the_image_has_no_sbin() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        install_init(&rootfs).unwrap();

        assert_eq!(
            std::fs::read_link(rootfs.join("sbin/init")).unwrap(),
            PathBuf::from(GUEST_INIT_SCRIPT_PATH)
        );
    }

    /// A merged-/usr image links `sbin` to `usr/sbin`; the init goes where
    /// the container will look for it.
    #[test]
    fn init_follows_a_relative_sbin_symlink_inside_the_rootfs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("usr/sbin")).unwrap();
        std::os::unix::fs::symlink("usr/sbin", rootfs.join("sbin")).unwrap();

        install_init(&rootfs).unwrap();

        assert_eq!(
            std::fs::read_link(rootfs.join("usr/sbin/init")).unwrap(),
            PathBuf::from(GUEST_INIT_SCRIPT_PATH)
        );
    }

    /// An absolute symlink in the image points inside the container, never at
    /// the host: `sbin -> /usr/sbin` must not reach the host's `/usr/sbin`.
    #[test]
    fn init_resolves_absolute_symlinks_against_the_rootfs() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        let host = temp_dir.path().join("host-usr-sbin");
        std::fs::create_dir_all(rootfs.join("usr/sbin")).unwrap();
        std::fs::create_dir_all(&host).unwrap();
        std::os::unix::fs::symlink("/usr/sbin", rootfs.join("sbin")).unwrap();
        // Would resolve out of the rootfs if `..` were not stopped at its root.
        std::os::unix::fs::symlink("../../../host-usr-sbin", rootfs.join("usr/escape")).unwrap();

        assert_eq!(
            resolve_in_rootfs(&rootfs, "/sbin/init").unwrap(),
            rootfs.join("usr/sbin/init")
        );
        assert_eq!(
            resolve_in_rootfs(&rootfs, "/usr/escape/init").unwrap(),
            rootfs.join("host-usr-sbin/init")
        );

        install_init(&rootfs).unwrap();
        assert!(rootfs.join("usr/sbin/init").symlink_metadata().is_ok());
        assert_eq!(std::fs::read_dir(&host).unwrap().count(), 0);
    }

    #[test]
    fn symlink_loops_in_the_image_are_an_error() {
        let temp_dir = tempfile::tempdir().unwrap();
        let rootfs = temp_dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::os::unix::fs::symlink("/sbin", rootfs.join("sbin")).unwrap();

        assert!(install_init(&rootfs).is_err());
    }

    #[tokio::test]
    async fn extract_supervisor_binary_cache_hit_and_miss() {
        let digest_hex = "ee".repeat(32);
        let digest = format!("sha256:{digest_hex}");
        let importer = Arc::new(MockImporter {
            digest_to_return: digest.clone(),
            import_calls: std::sync::atomic::AtomicUsize::new(0),
            extract_calls: std::sync::atomic::AtomicUsize::new(0),
            recorded_repo_digest: std::sync::Mutex::new(Vec::new()),
            import_delay: Duration::ZERO,
        });

        let alias_checker = Arc::new(MockAliasChecker {
            existing_aliases: std::sync::Mutex::new(std::collections::HashSet::new()),
        });

        let cache =
            ImageCache::with_checker(alias_checker, importer.clone(), "test-oci-".to_string());

        let temp_cache_dir = tempfile::tempdir().unwrap();

        // 1. First extraction is a cache miss
        let (bin_path1, dig1) = cache
            .extract_supervisor_binary(
                "ghcr.io/nvidia/openshell/supervisor:latest",
                temp_cache_dir.path(),
            )
            .await
            .unwrap();
        assert_eq!(dig1, digest);
        assert!(bin_path1.exists());
        assert_eq!(
            importer
                .extract_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // 2. Second extraction for same digest is a cache hit (calls extract_supervisor_binary on importer, but hits file check)
        let (bin_path2, dig2) = cache
            .extract_supervisor_binary(
                "ghcr.io/nvidia/openshell/supervisor:latest",
                temp_cache_dir.path(),
            )
            .await
            .unwrap();
        assert_eq!(dig2, digest);
        assert_eq!(bin_path1, bin_path2);
    }

    #[test]
    fn test_digest_of_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_bin");
        std::fs::write(&file_path, b"hello supervisor").unwrap();

        let digest = digest_of_file(&file_path).unwrap();
        // SHA-256("hello supervisor") = 13698ec9ad86f380ac98b76b758f96f23ed83b0107115f4dfee415be8a26fe38
        assert_eq!(
            digest,
            "sha256:13698ec9ad86f380ac98b76b758f96f23ed83b0107115f4dfee415be8a26fe38"
        );
    }

    #[test]
    fn digest_of_file_refuses_symlink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test_bin");
        std::fs::write(&file_path, b"hello supervisor").unwrap();
        let link_path = temp_dir.path().join("test_link");
        std::os::unix::fs::symlink(&file_path, &link_path).unwrap();

        let err = digest_of_file(&link_path).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }

    #[tokio::test]
    async fn extract_supervisor_binary_ignores_symlink_in_cache() {
        let digest_hex = "dd".repeat(32);
        let digest = format!("sha256:{digest_hex}");
        let importer = Arc::new(MockImporter {
            digest_to_return: digest.clone(),
            import_calls: std::sync::atomic::AtomicUsize::new(0),
            extract_calls: std::sync::atomic::AtomicUsize::new(0),
            recorded_repo_digest: std::sync::Mutex::new(Vec::new()),
            import_delay: Duration::ZERO,
        });

        let alias_checker = Arc::new(MockAliasChecker {
            existing_aliases: std::sync::Mutex::new(std::collections::HashSet::new()),
        });

        let _cache =
            ImageCache::with_checker(alias_checker, importer.clone(), "test-oci-".to_string());

        let temp_cache_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_cache_dir.path().join(&digest_hex);
        std::fs::create_dir_all(&target_dir).unwrap();
        let fake_target = temp_cache_dir.path().join("evil_target");
        std::fs::write(&fake_target, b"evil").unwrap();
        let symlink_bin = target_dir.join("openshell-sandbox");
        std::os::unix::fs::symlink(&fake_target, &symlink_bin).unwrap();

        // Cached binary is a symlink: must NOT be treated as a cache hit,
        // but re-extracted by importer.
        assert!(!is_valid_cached_binary(&symlink_bin).await);
    }

    #[tokio::test]
    async fn copy_extracted_binary_refuses_symlink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let host_file = temp_dir.path().join("host_secret");
        std::fs::write(&host_file, b"secret data").unwrap();

        let link_path = temp_dir.path().join("symlink_bin");
        std::os::unix::fs::symlink(&host_file, &link_path).unwrap();

        let target_path = temp_dir.path().join("target_bin");
        let err = copy_extracted_binary(&link_path, &target_path, "test:latest")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("symlink"));
        assert!(!target_path.exists());
    }

    #[tokio::test]
    async fn copy_extracted_binary_copies_regular_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let source_file = temp_dir.path().join("source_bin");
        std::fs::write(&source_file, b"binary content").unwrap();

        let target_path = temp_dir.path().join("target_bin");
        copy_extracted_binary(&source_file, &target_path, "test:latest")
            .await
            .unwrap();

        assert_eq!(std::fs::read(&target_path).unwrap(), b"binary content");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o755);
        }
    }
}
