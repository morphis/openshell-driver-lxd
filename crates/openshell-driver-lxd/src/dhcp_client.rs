// SPDX-License-Identifier: AGPL-3.0-or-later

//! DHCP client resolution and event script asset.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::DriverError;

/// Event script passed to udhcpc via `-s` to apply IP address and route.
pub(crate) const DHCP_CLIENT_SCRIPT: &[u8] = include_bytes!("../assets/dhcp-client/udhcpc.script");

/// Candidate binary names to look for in `PATH`.
const CANDIDATE_NAMES: &[&str] = &["busybox-static", "udhcpc", "busybox"];

/// Candidate binary names specifically for busybox.
const BUSYBOX_CANDIDATE_NAMES: &[&str] = &["busybox-static", "busybox"];

/// Candidate full paths to probe when not found in `PATH`.
const FALLBACK_PATHS: &[&str] = &[
    "/usr/bin/busybox-static",
    "/bin/busybox-static",
    "/usr/sbin/udhcpc",
    "/usr/bin/udhcpc",
    "/sbin/udhcpc",
    "/bin/udhcpc",
    "/usr/bin/busybox",
    "/bin/busybox",
];

/// Candidate full paths to probe for busybox when not found in `PATH`.
const BUSYBOX_FALLBACK_PATHS: &[&str] = &[
    "/usr/bin/busybox-static",
    "/bin/busybox-static",
    "/usr/bin/busybox",
    "/bin/busybox",
];

/// Relative paths within `$SNAP` to probe when running inside a snap.
const SNAP_RELATIVE_PATHS: &[&str] = &[
    "usr/bin/busybox-static",
    "bin/busybox-static",
    "usr/sbin/udhcpc",
    "usr/bin/udhcpc",
    "bin/udhcpc",
    "sbin/udhcpc",
    "usr/bin/busybox",
    "bin/busybox",
];

/// Relative paths within `$SNAP` to probe for busybox when running inside a snap.
const BUSYBOX_SNAP_RELATIVE_PATHS: &[&str] = &[
    "usr/bin/busybox-static",
    "bin/busybox-static",
    "usr/bin/busybox",
    "bin/busybox",
];

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn is_static_elf_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 52 || &bytes[0..4] != b"\x7fELF" {
        return false;
    }
    let ei_class = bytes[4];
    let ei_data = bytes[5];
    let is_le = match ei_data {
        1 => true,
        2 => false,
        _ => return false,
    };

    let read_u16 = |offset: usize| -> Option<u16> {
        let slice = bytes.get(offset..offset + 2)?;
        let arr: [u8; 2] = slice.try_into().ok()?;
        Some(if is_le {
            u16::from_le_bytes(arr)
        } else {
            u16::from_be_bytes(arr)
        })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let slice = bytes.get(offset..offset + 4)?;
        let arr: [u8; 4] = slice.try_into().ok()?;
        Some(if is_le {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        })
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        let slice = bytes.get(offset..offset + 8)?;
        let arr: [u8; 8] = slice.try_into().ok()?;
        Some(if is_le {
            u64::from_le_bytes(arr)
        } else {
            u64::from_be_bytes(arr)
        })
    };

    let e_type = match read_u16(16) {
        Some(t) => t,
        None => return false,
    };
    // ET_EXEC (2) or ET_DYN (3, static-PIE executables are ET_DYN)
    if e_type != 2 && e_type != 3 {
        return false;
    }

    let (e_phoff, e_phentsize, e_phnum) = match ei_class {
        1 => {
            // 32-bit ELF
            let phoff = match read_u32(28) {
                Some(v) => v as usize,
                None => return false,
            };
            let phentsize = match read_u16(42) {
                Some(v) => v as usize,
                None => return false,
            };
            let phnum = match read_u16(44) {
                Some(v) => v as usize,
                None => return false,
            };
            (phoff, phentsize, phnum)
        }
        2 => {
            // 64-bit ELF
            if bytes.len() < 64 {
                return false;
            }
            let phoff = match read_u64(32) {
                Some(v) => v as usize,
                None => return false,
            };
            let phentsize = match read_u16(54) {
                Some(v) => v as usize,
                None => return false,
            };
            let phnum = match read_u16(56) {
                Some(v) => v as usize,
                None => return false,
            };
            (phoff, phentsize, phnum)
        }
        _ => return false,
    };

    if e_phnum == 0 || e_phentsize < 4 {
        return false;
    }

    const PT_INTERP: u32 = 3;
    for i in 0..e_phnum {
        let ph_offset = match e_phoff.checked_add(match i.checked_mul(e_phentsize) {
            Some(o) => o,
            None => return false,
        }) {
            Some(o) => o,
            None => return false,
        };
        let p_type = match read_u32(ph_offset) {
            Some(t) => t,
            None => return false,
        };
        if p_type == PT_INTERP {
            return false;
        }
    }

    true
}

fn is_static_elf(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut buffer = Vec::new();
    let mut handle = file.take(65536);
    if handle.read_to_end(&mut buffer).is_err() || buffer.len() < 52 {
        return false;
    }
    is_static_elf_bytes(&buffer)
}

fn is_candidate(path: &Path) -> bool {
    is_executable(path) && is_static_elf(path)
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if is_candidate(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Resolves a DHCP client binary from the environment or the given override path.
pub fn resolve_dhcp_client_binary(override_path: Option<&Path>) -> Result<PathBuf, DriverError> {
    if let Some(path) = override_path {
        if !is_executable(path) {
            return Err(DriverError::DhcpClient(format!(
                "configured DHCP client binary {path:?} does not exist or is not executable"
            )));
        }
        if !is_static_elf(path) {
            return Err(DriverError::DhcpClient(format!(
                "configured DHCP client binary {path:?} is dynamically linked or not a static ELF executable; fallback DHCP client must be statically linked"
            )));
        }
        return Ok(path.to_path_buf());
    }

    for name in CANDIDATE_NAMES {
        if let Some(p) = find_in_path(name) {
            return Ok(p);
        }
    }

    if let Ok(snap) = std::env::var("SNAP") {
        let snap_dir = Path::new(&snap);
        for sub in SNAP_RELATIVE_PATHS {
            let candidate = snap_dir.join(sub);
            if is_candidate(&candidate) {
                return Ok(candidate);
            }
        }
    }

    for path_str in FALLBACK_PATHS {
        let p = Path::new(path_str);
        if is_candidate(p) {
            return Ok(p.to_path_buf());
        }
    }

    Err(DriverError::DhcpClient(
        "no DHCP client binary found in environment; install udhcpc or busybox-static, or pass --dhcp-client-bin".into(),
    ))
}

/// Resolves a static busybox binary from the host environment to provide a shell and coreutils.
pub fn resolve_static_busybox() -> Result<PathBuf, DriverError> {
    for name in BUSYBOX_CANDIDATE_NAMES {
        if let Some(p) = find_in_path(name) {
            return Ok(p);
        }
    }

    if let Ok(snap) = std::env::var("SNAP") {
        let snap_dir = Path::new(&snap);
        for sub in BUSYBOX_SNAP_RELATIVE_PATHS {
            let candidate = snap_dir.join(sub);
            if is_candidate(&candidate) {
                return Ok(candidate);
            }
        }
    }

    for path_str in BUSYBOX_FALLBACK_PATHS {
        let p = Path::new(path_str);
        if is_candidate(p) {
            return Ok(p.to_path_buf());
        }
    }

    Err(DriverError::ImageImport(
        "no static busybox binary found on host; install busybox-static or busybox".into(),
    ))
}

/// Computes a sha256 digest over everything the guest network volume holds, so
/// that changing any of it gives a new, distinctly named volume.
#[must_use]
pub(crate) fn dhcp_client_digest(binary_bytes: &[u8], busybox_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    // Length-prefixed, and with a layout revision, so the digest covers how
    // the volume is laid out and not only what is in it: concatenating three
    // blobs cannot tell `ab|c` from `a|bc`, and renaming an entry or changing
    // its mode would otherwise reuse a volume built the old way.
    hasher.update(VOLUME_LAYOUT_REVISION.to_be_bytes());
    for part in [binary_bytes, busybox_bytes, DHCP_CLIENT_SCRIPT] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Bumped whenever the guest network volume's entry names or modes change,
/// so hosts holding one built the old way build a new one.
const VOLUME_LAYOUT_REVISION: u64 = 1;

/// What a sandbox's guest-side network volume holds.
///
/// The busybox is resolved separately from the DHCP client, and deliberately:
/// the DHCP client may be a standalone `udhcpc` rather than a busybox — that
/// is what [`CANDIDATE_NAMES`] allows — and the init scripts run their shell
/// and their applets through the busybox by name. Publishing a standalone
/// `udhcpc` under that name would give them an interpreter that is not a
/// shell, and no sandbox would boot.
pub struct GuestNetTools {
    /// Published as `udhcpc`, and invoked under that name so busybox's
    /// `argv[0]` dispatch reaches the right applet.
    pub dhcp_client: Vec<u8>,
    /// Published as `busybox`: the init script's interpreter, and every
    /// program it runs before the workload boundary takes over.
    pub busybox: Vec<u8>,
    pub digest: String,
}

/// Loads the guest-side network tooling from the environment (or the
/// configured DHCP client override).
pub async fn load_guest_net_tools(
    override_path: Option<&Path>,
) -> Result<GuestNetTools, DriverError> {
    let read = |path: PathBuf, what: &'static str| async move {
        tokio::fs::read(&path).await.map_err(move |e| {
            DriverError::DhcpClient(format!("failed to read {what} from {path:?}: {e}"))
        })
    };

    let dhcp_client = read(
        resolve_dhcp_client_binary(override_path)?,
        "DHCP client binary",
    )
    .await?;
    let busybox = read(resolve_static_busybox()?, "static busybox binary").await?;
    let digest = dhcp_client_digest(&dhcp_client, &busybox);
    Ok(GuestNetTools {
        dhcp_client,
        busybox,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_asset_is_non_empty() {
        assert!(!DHCP_CLIENT_SCRIPT.is_empty());
    }

    #[test]
    fn digest_computation_is_deterministic_and_valid() {
        let digest1 = dhcp_client_digest(b"dummy-udhcpc-1", b"dummy-busybox");
        let digest2 = dhcp_client_digest(b"dummy-udhcpc-1", b"dummy-busybox");
        let digest3 = dhcp_client_digest(b"dummy-udhcpc-2", b"dummy-busybox");

        assert_eq!(digest1, digest2);
        assert_ne!(digest1, digest3);
        assert!(digest1.starts_with("sha256:"));
        assert_eq!(digest1.len(), 7 + 64);
    }

    #[cfg(unix)]
    fn create_dummy_elf_binary(is_static: bool) -> tempfile::NamedTempFile {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut data = vec![0u8; 64 + 56];
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian
        data[6] = 1; // version
        data[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        data[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff = 64
        data[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize = 64
        data[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize = 56
        data[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum = 1

        let pt_type: u32 = if is_static { 1 } else { 3 }; // 1 = PT_LOAD, 3 = PT_INTERP
        data[64..68].copy_from_slice(&pt_type.to_le_bytes());

        file.write_all(&data).unwrap();
        file.flush().unwrap();
        let mut perms = std::fs::metadata(file.path()).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(file.path(), perms).unwrap();
        file
    }

    #[test]
    #[cfg(unix)]
    fn resolve_with_override_existing() {
        let dummy = create_dummy_elf_binary(true);
        let resolved = resolve_dhcp_client_binary(Some(dummy.path())).unwrap();
        assert_eq!(resolved, dummy.path());
    }

    #[test]
    #[cfg(unix)]
    fn resolve_with_override_rejects_dynamic_binary() {
        let dummy = create_dummy_elf_binary(false);
        let err = resolve_dhcp_client_binary(Some(dummy.path())).unwrap_err();
        assert!(err.to_string().contains("dynamically linked"));
    }

    #[test]
    fn resolve_with_override_missing() {
        let missing = Path::new("/path/to/nonexistent/dhcp-client-xyz");
        let err = resolve_dhcp_client_binary(Some(missing)).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn load_guest_net_tools_with_dummy_executable() {
        if resolve_static_busybox().is_err() {
            // No busybox on this host; the init scripts' interpreter cannot
            // be staged and the path under test is unreachable.
            return;
        }
        let dummy = create_dummy_elf_binary(true);
        let tools = load_guest_net_tools(Some(dummy.path())).await.unwrap();
        assert!(!tools.dhcp_client.is_empty());
        assert!(!tools.busybox.is_empty());
        assert!(tools.digest.starts_with("sha256:"));
        // The DHCP client override must not be published as the busybox: the
        // init scripts would get an interpreter that is not a shell.
        assert_ne!(tools.dhcp_client, tools.busybox);
    }

    /// The volume is digest-keyed, so a busybox change has to reach the name
    /// or hosts keep mounting the old one.
    #[test]
    fn the_digest_covers_the_busybox_too() {
        assert_ne!(
            dhcp_client_digest(b"udhcpc", b"busybox-1"),
            dhcp_client_digest(b"udhcpc", b"busybox-2")
        );
    }
}
