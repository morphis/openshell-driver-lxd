// SPDX-License-Identifier: AGPL-3.0-or-later

//! RFC 0012 isolation-backend contract artifacts.
//!
//! OpenShell v0.1.0 split the monolithic supervisor into an out-of-workload
//! companion (`openshell-supervisor`) and an in-workload boundary
//! (`openshell-sandbox`). The driver provisions both halves and hands each the
//! protected file it needs:
//!
//! | File | Consumer | Shape |
//! |---|---|---|
//! | [`GUEST_RUNTIME_DESCRIPTOR_PATH`] | companion, `--backend-descriptor-file` | [`SandboxRuntimeDescriptor`] |
//! | [`GUEST_AUTH_BUNDLE_PATH`] | companion, `--auth-bundle-file` | the gateway's `supervisor` bundle, verbatim |
//! | [`GUEST_BOOTSTRAP_PATH`] | workload, `--bootstrap` | [`BoundaryConfig`] |
//!
//! Upstream deserializes every one of these with `deny_unknown_fields`, so the
//! shapes here mirror `openshell-sandbox-backend::boundary_protocol` and
//! `openshell-isolation-interface::contract` field for field. They are
//! reimplemented rather than imported because this driver is out-of-tree and
//! vendors only the proto contract — which means a drift in either direction
//! is only caught at runtime, by a sandbox that fails to attach. When changing
//! anything here, check it against the pinned revision's own deserializers
//! rather than against this file's tests.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::DriverError;

/// Name the companion's OpenShell sandbox backend registers under.
///
/// The companion is told this out of band, in
/// [`ENV_ADMITTED_ISOLATION_BACKEND`], rather than reading it from the
/// descriptor: upstream verifies the descriptor *against* the admitted backend,
/// so taking both from the same file would make that check self-referential.
pub const BACKEND_NAME: &str = "openshell-sandbox";

/// Environment variable naming the isolation backend admitted for this sandbox.
pub const ENV_ADMITTED_ISOLATION_BACKEND: &str = "OPENSHELL_ADMITTED_ISOLATION_BACKEND";

/// TCP port the in-workload boundary listens on for the Sandbox Protocol.
pub const BOUNDARY_PORT: u16 = 50051;

/// Guest path of the companion's backend descriptor (`--backend-descriptor-file`).
pub const GUEST_RUNTIME_DESCRIPTOR_PATH: &str = "/etc/openshell/runtime/backend-descriptor.json";

/// Guest path of the companion's authentication bundle (`--auth-bundle-file`).
pub const GUEST_AUTH_BUNDLE_PATH: &str = "/etc/openshell/runtime/auth-bundle.json";

/// Guest directory holding the files the workload boundary itself reads.
///
/// Separate from the runtime directory, and owned by the boundary's own uid:
/// the bootstrap is one-use and the boundary deletes it after reading, which
/// needs write access to the directory. Keeping it apart means the boundary's
/// write access does not extend to anything the trusted side staged.
pub const GUEST_BOUNDARY_DIR: &str = "/etc/openshell/boundary";

/// Guest path of the workload boundary's bootstrap config (`--bootstrap`).
pub const GUEST_BOOTSTRAP_PATH: &str = "/etc/openshell/boundary/bootstrap.json";

/// Guest path of the workload boundary's TLS server certificate chain.
pub const GUEST_BOUNDARY_TLS_CERT_PATH: &str = "/etc/openshell/boundary/server.crt";

/// Guest path of the workload boundary's TLS server private key.
pub const GUEST_BOUNDARY_TLS_KEY_PATH: &str = "/etc/openshell/boundary/server.key";

/// Guest directory the workload boundary installs its proxy CA material in.
///
/// The boundary creates and chmods this itself, but `/run` belongs to root and
/// the boundary does not, so the directory is pre-created for it. Nothing
/// mounts a tmpfs over `/run` here — the container's init is this driver's
/// script, not systemd — so a directory staged before start survives.
pub const GUEST_SUPERVISOR_CA_DIR: &str = "/run/openshell-supervisor-ca";

/// Guest path of the identity the workload boundary must run as.
///
/// `openshell-sandbox` refuses to start as root, and an LXD container's init is
/// always root, so the init script hands these to the boundary's own
/// `launch-capability-free`, which drops to them. The same numbers are in the
/// bootstrap, but a shell script should not have to parse JSON to find them.
///
/// Format: one line, `uid gid`. No supplementary groups: the drop clears them
/// (see [`resolve_workload_identity`]).
pub const GUEST_WORKLOAD_IDENTITY_PATH: &str = "/etc/openshell/runtime/workload-identity";

// --- Gateway-minted launch credentials ---------------------------------------

/// One accepted public key from the immutable sandbox verification bundle.
///
/// `public_key_pem` is bytes on the wire (upstream's `SessionVerificationKey`
/// declares `Vec<u8>`), but a UTF-8 string in [`GatewayVerificationKey`], the
/// shape the workload boundary reads.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionVerificationKey {
    pub key_id: String,
    pub public_key_pem: Vec<u8>,
}

/// The subset of the gateway's `SupervisorAuthBundle` the driver reads.
///
/// The bearer tokens are deliberately absent: the bundle is forwarded to the
/// companion verbatim, so the driver never needs to parse — or log — them.
#[derive(Debug, Clone, Deserialize)]
pub struct SupervisorAuthBundleView {
    pub session_id: String,
    pub runtime_generation: String,
    pub session_rotation: u64,
    pub auth_epoch: u64,
}

/// Gateway-created launch credentials, from `DriverSandboxSpec.launch_authentication`.
///
/// The driver splits this: the companion receives [`Self::supervisor_bundle`]
/// unchanged, while the workload boundary receives only the gateway identity
/// and public verification keys. The supervisor bearer tokens must never reach
/// the workload.
#[derive(Clone)]
pub struct LaunchAuthentication {
    supervisor: serde_json::Value,
    pub view: SupervisorAuthBundleView,
    pub gateway_id: String,
    pub verification_keys: Vec<SessionVerificationKey>,
}

/// Hand-written so the supervisor bundle — which holds the gateway and
/// sandbox bearer tokens verbatim — cannot reach a log through `{:?}`.
/// Upstream redacts every type that carries one.
impl std::fmt::Debug for LaunchAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchAuthentication")
            .field("supervisor", &"<redacted>")
            .field("gateway_id", &self.gateway_id)
            .field(
                "verification_key_ids",
                &self
                    .verification_keys
                    .iter()
                    .map(|key| key.key_id.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Deserialize)]
struct LaunchAuthenticationWire {
    supervisor: serde_json::Value,
    gateway_id: String,
    verification_keys: Vec<SessionVerificationKey>,
}

impl LaunchAuthentication {
    /// Decodes the gateway's opaque launch credentials.
    ///
    /// The `supervisor` half is retained as raw JSON so it reaches the
    /// companion exactly as the gateway minted it, even if upstream adds
    /// fields this driver does not know about.
    pub fn decode(encoded: &[u8]) -> Result<Self, DriverError> {
        if encoded.is_empty() {
            return Err(DriverError::InvalidArgument(
                "launch_authentication is required: the gateway mints the credentials the \
                 supervisor companion and workload boundary authenticate with"
                    .to_string(),
            ));
        }
        let wire: LaunchAuthenticationWire = serde_json::from_slice(encoded).map_err(|e| {
            DriverError::InvalidArgument(format!("decode launch_authentication: {e}"))
        })?;
        let view: SupervisorAuthBundleView = serde_json::from_value(wire.supervisor.clone())
            .map_err(|e| {
                DriverError::InvalidArgument(format!(
                    "decode launch_authentication.supervisor: {e}"
                ))
            })?;
        if wire.gateway_id.is_empty() {
            return Err(DriverError::InvalidArgument(
                "launch_authentication.gateway_id is empty".to_string(),
            ));
        }
        if wire.verification_keys.is_empty() {
            return Err(DriverError::InvalidArgument(
                "launch_authentication.verification_keys is empty".to_string(),
            ));
        }
        Ok(Self {
            supervisor: wire.supervisor,
            view,
            gateway_id: wire.gateway_id,
            verification_keys: wire.verification_keys,
        })
    }

    /// The companion's `--auth-bundle-file` contents: the gateway's supervisor
    /// bundle, unchanged.
    pub fn supervisor_bundle(&self) -> Result<Vec<u8>, DriverError> {
        serde_json::to_vec(&self.supervisor)
            .map_err(|e| DriverError::Internal(format!("serialize supervisor auth bundle: {e}")))
    }

    /// The public verification keys, in the workload boundary's shape.
    pub fn gateway_verification_keys(&self) -> Result<Vec<GatewayVerificationKey>, DriverError> {
        self.verification_keys
            .iter()
            .map(|key| {
                String::from_utf8(key.public_key_pem.clone())
                    .map(|public_key_pem| GatewayVerificationKey {
                        key_id: key.key_id.clone(),
                        public_key_pem,
                    })
                    .map_err(|e| {
                        DriverError::InvalidArgument(format!(
                            "verification key {:?} is not valid UTF-8 PEM: {e}",
                            key.key_id
                        ))
                    })
            })
            .collect()
    }
}

// --- Contract types ----------------------------------------------------------

/// Public verification key staged in the workload boundary's bootstrap.
#[derive(Debug, Clone, Serialize)]
pub struct GatewayVerificationKey {
    pub key_id: String,
    pub public_key_pem: String,
}

/// Exact immutable identity applied to the workload process.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedWorkloadIdentity {
    pub uid: u32,
    pub gid: u32,
    /// Sorted and deduplicated; never contains `gid` or zero.
    pub supplementary_gids: Vec<u32>,
    /// Where the identity came from: `policy`, `template`, or `image`.
    pub source: String,
    /// Immutable identifier of the image the identity was resolved against.
    ///
    /// This driver passes its LXD image alias, which embeds the OCI digest and
    /// the conversion revision. Upstream treats the field as opaque evidence,
    /// and the alias is the coordinate that actually pins what was booted.
    pub resource_digest: String,
}

/// A backend-neutral security property established by whatever owns the outer
/// network fence.
///
/// Mirrors `openshell_isolation_interface::contract::OuterFenceGuarantee`.
/// Declaration order is the sort order, and upstream holds these in a
/// `BTreeSet`, so [`BTreeSet`] here produces the same JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OuterFenceGuarantee {
    /// No workload packet can leave without an explicit mediated decision.
    DefaultDenyEgress,
    /// No network path was found outside the mediated boundary.
    NoUnmanagedEgressPath,
    /// Access already granted can be revoked by the fence's owner.
    RevocationVerified,
    /// Losing the fence's controller does not open network access.
    ControllerLossFailsClosed,
}

/// Backend-neutral projection of the validated outer network fence.
///
/// Mirrors `openshell_isolation_interface::contract::OuterFenceGuarantees`,
/// which replaced the per-driver `DriverFenceEvidence` enum in upstream
/// #3366. That enum was closed over the four in-tree drivers, which is why an
/// earlier attempt at this work had to patch upstream to add an `Lxd` variant;
/// a projection needs no such thing, and this driver attests its own fence.
///
/// Both halves of the sandbox validate it before the workload runs, and
/// **all four guarantees are required** — an incomplete set is rejected, so a
/// sandbox the driver cannot fence is a sandbox that never attaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OuterFenceGuarantees {
    /// The generation the evidence was collected for.
    pub generation: String,
    /// Every guarantee established, normalized.
    pub established: BTreeSet<OuterFenceGuarantee>,
    /// Commitment to the native evidence below, as 64 lowercase hex digits.
    pub evidence_digest: String,
}

/// What the driver actually observed about one workload's LXD networking.
///
/// This is the native evidence the digest commits to. Upstream never reads it
/// — it only compares the projection and the digest — but the digest binds the
/// projection to these exact observations, so a fence attested for one
/// instance, network or ACL cannot be replayed for another.
#[derive(Debug, Clone, Serialize)]
pub struct LxdFenceEvidence {
    /// The workload instance the fence was installed on.
    pub instance_name: String,
    /// The single managed network the workload's NIC attaches to.
    pub network: String,
    /// The network's LXD type. Only `ovn` can carry a per-NIC ACL.
    pub network_type: String,
    /// The driver-managed egress ACL on the workload's NIC.
    pub egress_acl: String,
    /// Any further network the workload was found attached to.
    pub unexpected_networks: Vec<String>,
}

impl LxdFenceEvidence {
    /// Projects these observations into the guarantees they actually
    /// establish, refusing to attest a fence that is not there.
    ///
    /// The ACL is what makes the four guarantees true, and it is an OVN
    /// per-NIC ACL with both default actions set to `reject`:
    ///
    /// - egress is denied by default, and only the rules the driver wrote let
    ///   anything out, so nothing leaves unmediated;
    /// - the rules live in LXD, which applies a change to a running NIC, so
    ///   access already granted can be taken back;
    /// - and they are enforced by OVN rather than by the supervisor
    ///   companion, so the fence outlives the process that drives it.
    ///
    /// The last guarantee is separate: a second NIC would be an egress path
    /// no ACL of this driver's covers, so it is read back from the created
    /// instance rather than assumed from the request.
    pub fn project(&self, generation: &str) -> Result<OuterFenceGuarantees, DriverError> {
        let mut established = BTreeSet::new();
        if !self.egress_acl.is_empty() {
            established.extend([
                OuterFenceGuarantee::DefaultDenyEgress,
                OuterFenceGuarantee::RevocationVerified,
                OuterFenceGuarantee::ControllerLossFailsClosed,
            ]);
        }
        if self.unexpected_networks.is_empty() {
            established.insert(OuterFenceGuarantee::NoUnmanagedEgressPath);
        }
        let evidence = serde_json::to_vec(self)
            .map_err(|e| DriverError::Internal(format!("serialize outer fence evidence: {e}")))?;
        let guarantees = OuterFenceGuarantees {
            generation: generation.to_string(),
            established,
            evidence_digest: evidence_digest(generation, &evidence),
        };
        guarantees.validate(generation)?;
        Ok(guarantees)
    }
}

impl OuterFenceGuarantees {
    /// Refuses an incomplete fence here, where the reason is legible, rather
    /// than letting the sandbox refuse it later with upstream's own wording.
    pub fn validate(&self, expected_generation: &str) -> Result<(), DriverError> {
        let required = BTreeSet::from([
            OuterFenceGuarantee::DefaultDenyEgress,
            OuterFenceGuarantee::NoUnmanagedEgressPath,
            OuterFenceGuarantee::RevocationVerified,
            OuterFenceGuarantee::ControllerLossFailsClosed,
        ]);
        if self.generation != expected_generation {
            return Err(DriverError::Internal(format!(
                "outer fence was collected for generation {:?}, not {expected_generation:?}",
                self.generation
            )));
        }
        let missing: Vec<&OuterFenceGuarantee> = required.difference(&self.established).collect();
        if !missing.is_empty() {
            return Err(DriverError::FailedPrecondition(format!(
                "the sandbox's outer network fence establishes none of {missing:?}: OpenShell \
                 v0.1.0 requires every one of them before a workload runs. Sandboxes need an \
                 OVN network, which is the only kind LXD applies a per-NIC ACL to, and a NIC \
                 with no second network on it"
            )));
        }
        Ok(())
    }
}

/// Rejects claims upstream would reject.
///
/// Both halves of the sandbox run this check on what the driver wrote, and
/// fail closed, so an empty project name or an alias with a space in it would
/// otherwise surface as a sandbox that will not attach rather than as a bad
/// claim.
fn validate_resource_claims(claims: &BTreeMap<String, String>) -> Result<(), DriverError> {
    for (key, value) in claims {
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(DriverError::Internal(format!(
                "boundary resource-claim keys must be non-empty and contain no whitespace: {key:?}"
            )));
        }
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            return Err(DriverError::Internal(format!(
                "boundary resource claim {key:?} must be non-empty and contain no whitespace"
            )));
        }
    }
    Ok(())
}

/// Upstream's binding of a generation to its native evidence:
/// the generation's length as a big-endian `u64`, the generation, the
/// evidence, hashed with SHA-256 and rendered as lowercase hex.
fn evidence_digest(generation: &str, evidence: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    let mut binding = Vec::with_capacity(8 + generation.len() + evidence.len());
    binding.extend_from_slice(&(generation.len() as u64).to_be_bytes());
    binding.extend_from_slice(generation.as_bytes());
    binding.extend_from_slice(evidence);
    Sha256::digest(&binding)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Driver-provisioned byte-stream endpoint the companion dials.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SandboxTransport {
    Tcp {
        /// Stable logical authority, used for diagnostics.
        authority: String,
        /// Explicit connection candidates resolved by the driver.
        addresses: Vec<SocketAddr>,
    },
}

/// Companion-side, generation-pinned TLS server authentication.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxTlsClientConfig {
    pub server_name: String,
    pub trust_anchor_pem: String,
}

/// Workload-side TLS server material, by guest path.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxTlsServerConfig {
    pub certificate_chain_path: String,
    pub private_key_path: String,
}

/// Driver-provisioned listener the workload boundary binds.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BoundaryListener {
    TlsTcp {
        address: SocketAddr,
        tls: SandboxTlsServerConfig,
    },
}

/// Protected runtime descriptor consumed by the companion supervisor.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxRuntimeDescriptor {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: String,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub transport: SandboxTransport,
    pub tls: SandboxTlsClientConfig,
    pub host_gateway_ip: Option<std::net::IpAddr>,
    pub resource_claims: BTreeMap<String, String>,
    pub outer_fence: OuterFenceGuarantees,
}

/// Protected bootstrap configuration consumed by the workload boundary.
#[derive(Debug, Clone, Serialize)]
pub struct BoundaryConfig {
    pub boundary_id: String,
    pub generation: String,
    pub session_id: String,
    pub session_rotation: u64,
    pub auth_epoch: u64,
    pub gateway_id: String,
    pub verification_keys: Vec<GatewayVerificationKey>,
    pub listener: BoundaryListener,
    pub resource_claims: BTreeMap<String, String>,
    pub resource_claim_files: BTreeMap<String, String>,
    pub workload_identity: ResolvedWorkloadIdentity,
    pub outer_fence: OuterFenceGuarantees,
    pub child_env: HashMap<String, String>,
}

// --- Artifact staging --------------------------------------------------------

/// A protected file staged into a guest, with the owner that must read it.
pub struct GuestFile {
    pub path: &'static str,
    pub contents: Vec<u8>,
    /// Container-side owner. The workload boundary runs unprivileged, so its
    /// own files cannot be left root-owned.
    pub uid: u32,
    pub gid: u32,
    pub mode: &'static str,
}

/// Builds the protected artifacts for one sandbox launch.
///
/// Create and start-from-stopped stage exactly the same things: RFC 0012 gives
/// every launch a fresh session, so a restarted sandbox gets new TLS material
/// and a new descriptor rather than reusing the previous generation's, which
/// the boundary would reject.
pub struct BoundaryArtifacts {
    boundary_id: String,
    generation: String,
    session_id: String,
    identity: ResolvedWorkloadIdentity,
    fence: OuterFenceGuarantees,
    resource_claims: BTreeMap<String, String>,
    tls: SandboxTlsMaterial,
}

impl BoundaryArtifacts {
    /// Projects the fence with this launch's generation rather than taking a
    /// projection, so the evidence and the descriptor that carries it cannot
    /// disagree about which generation was fenced — a mismatch both halves of
    /// the sandbox reject.
    pub fn new(
        boundary_id: &str,
        launch: &LaunchAuthentication,
        identity: ResolvedWorkloadIdentity,
        fence: &LxdFenceEvidence,
        resource_claims: BTreeMap<String, String>,
    ) -> Result<Self, DriverError> {
        let generation = launch.view.runtime_generation.clone();
        validate_resource_claims(&resource_claims)?;
        Ok(Self {
            fence: fence.project(&generation)?,
            boundary_id: boundary_id.to_string(),
            generation,
            session_id: launch.view.session_id.clone(),
            identity,
            resource_claims,
            tls: generate_sandbox_tls_material(&launch.view.session_id)?,
        })
    }

    /// The identity the workload boundary runs as.
    pub fn identity(&self) -> &ResolvedWorkloadIdentity {
        &self.identity
    }

    /// Files staged into the workload container before it starts: the boundary
    /// bootstrap and the TLS identity its listener presents.
    pub fn workload_files(
        &self,
        launch: &LaunchAuthentication,
        child_env: HashMap<String, String>,
    ) -> Result<Vec<GuestFile>, DriverError> {
        let boundary = BoundaryConfig {
            boundary_id: self.boundary_id.clone(),
            generation: self.generation.clone(),
            session_id: self.session_id.clone(),
            session_rotation: launch.view.session_rotation,
            auth_epoch: launch.view.auth_epoch,
            gateway_id: launch.gateway_id.clone(),
            verification_keys: launch.gateway_verification_keys()?,
            listener: BoundaryListener::TlsTcp {
                address: std::net::SocketAddr::from((
                    std::net::Ipv4Addr::UNSPECIFIED,
                    BOUNDARY_PORT,
                )),
                tls: SandboxTlsServerConfig {
                    certificate_chain_path: GUEST_BOUNDARY_TLS_CERT_PATH.to_string(),
                    private_key_path: GUEST_BOUNDARY_TLS_KEY_PATH.to_string(),
                },
            },
            resource_claims: self.resource_claims.clone(),
            resource_claim_files: BTreeMap::new(),
            workload_identity: self.identity.clone(),
            outer_fence: self.fence.clone(),
            child_env,
        };
        let (uid, gid) = (self.identity.uid, self.identity.gid);
        Ok(vec![
            // Read by the init script while it is still root, before it drops
            // to the identity this file names, so it stays root-owned.
            GuestFile {
                path: GUEST_WORKLOAD_IDENTITY_PATH,
                contents: format!("{uid} {gid}\n").into_bytes(),
                uid: 0,
                gid: 0,
                mode: "0400",
            },
            // The rest are read by the boundary itself, after the drop.
            GuestFile {
                path: GUEST_BOOTSTRAP_PATH,
                contents: serde_json::to_vec_pretty(&boundary).map_err(|e| {
                    DriverError::Internal(format!("serialize boundary bootstrap: {e}"))
                })?,
                uid,
                gid,
                mode: "0400",
            },
            GuestFile {
                path: GUEST_BOUNDARY_TLS_CERT_PATH,
                contents: self.tls.certificate_chain_pem.clone().into_bytes(),
                uid,
                gid,
                mode: "0444",
            },
            GuestFile {
                path: GUEST_BOUNDARY_TLS_KEY_PATH,
                contents: self.tls.private_key_pem.clone().into_bytes(),
                uid,
                gid,
                mode: "0400",
            },
        ])
    }

    /// The companion's backend descriptor, which can only be built once the
    /// workload has the address the companion dials.
    pub fn descriptor_file(
        &self,
        instance_name: &str,
        workload_ip: std::net::Ipv4Addr,
    ) -> Result<(&'static str, Vec<u8>), DriverError> {
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: self.boundary_id.clone(),
            generation: self.generation.clone(),
            session_id: self.session_id.clone(),
            workload_identity: self.identity.clone(),
            transport: SandboxTransport::Tcp {
                authority: format!("{instance_name}:{BOUNDARY_PORT}"),
                addresses: vec![std::net::SocketAddr::from((workload_ip, BOUNDARY_PORT))],
            },
            tls: SandboxTlsClientConfig {
                server_name: self.tls.server_name.clone(),
                trust_anchor_pem: self.tls.trust_anchor_pem.clone(),
            },
            host_gateway_ip: None,
            resource_claims: self.resource_claims.clone(),
            outer_fence: self.fence.clone(),
        };
        Ok((
            GUEST_RUNTIME_DESCRIPTOR_PATH,
            serde_json::to_vec_pretty(&descriptor)
                .map_err(|e| DriverError::Internal(format!("serialize backend descriptor: {e}")))?,
        ))
    }
}

// --- Workload identity -------------------------------------------------------

/// Conventional unprivileged account OpenShell sandbox images ship.
const DEFAULT_SANDBOX_USER: &str = "sandbox";

/// Resolves the immutable numeric identity the workload runs as.
///
/// Resolution order, narrowest first:
///
/// 1. `spec.workload_identity`, the selectors admitted by the gateway;
/// 2. the conventional [`DEFAULT_SANDBOX_USER`] account, when the image ships one.
///
/// Both are resolved against the pinned image's own `/etc/passwd` and
/// `/etc/group`, never against the host: the numbers must mean the same thing
/// inside the container as they do in the boundary's confirmation. Root is
/// rejected — upstream treats UID or GID zero as invalid for a capability-free
/// sandbox.
pub fn resolve_workload_identity(
    requested_user: &str,
    requested_group: &str,
    passwd: &[u8],
    group: &[u8],
    resource_digest: &str,
) -> Result<ResolvedWorkloadIdentity, DriverError> {
    let invalid = |msg: String| DriverError::InvalidArgument(msg);
    let passwd = String::from_utf8_lossy(passwd);
    let group = String::from_utf8_lossy(group);

    // name, uid, gid
    let accounts: Vec<(&str, u32, u32)> = passwd
        .lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            f.next()?;
            Some((name, f.next()?.parse().ok()?, f.next()?.parse().ok()?))
        })
        .collect();
    // name, gid, members
    let groups: Vec<(&str, u32, &str)> = group
        .lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            f.next()?;
            Some((name, f.next()?.parse().ok()?, f.next().unwrap_or("")))
        })
        .collect();

    let requested_user = requested_user.trim();
    let requested_group = requested_group.trim();
    let source = if requested_user.is_empty() && requested_group.is_empty() {
        "image"
    } else {
        "policy"
    };
    let user = if requested_user.is_empty() {
        DEFAULT_SANDBOX_USER
    } else {
        requested_user
    };

    let account = accounts
        .iter()
        .find(|(name, uid, _)| *name == user || user.parse::<u32>().ok() == Some(*uid));
    let uid: u32 = user
        .parse()
        .ok()
        .or_else(|| account.map(|(_, uid, _)| *uid))
        .ok_or_else(|| {
            invalid(format!(
                "workload user {user:?} is not present in the pinned image; set \
                 spec.workload_identity.user to an account the image defines"
            ))
        })?;
    let gid: u32 = if requested_group.is_empty() {
        account.map(|(_, _, gid)| *gid)
    } else {
        requested_group.parse().ok().or_else(|| {
            groups
                .iter()
                .find(|(name, _, _)| *name == requested_group)
                .map(|(_, gid, _)| *gid)
        })
    }
    .ok_or_else(|| {
        invalid(format!(
            "cannot resolve a group for workload user {user:?}; set \
             spec.workload_identity.group explicitly"
        ))
    })?;

    if uid == 0 || gid == 0 {
        return Err(invalid(format!(
            "workload identity {uid}:{gid} is root; OpenShell requires an \
             unprivileged workload user"
        )));
    }

    Ok(ResolvedWorkloadIdentity {
        // Always empty, and it has to be. The boundary's own
        // `launch-capability-free`, which the init script execs to drop
        // privilege, clears the supplementary set outright
        // (`setgroups(0, NULL)`) before it reads the bootstrap — and then
        // compares what it is actually running as against this list, exactly,
        // unless a GPU or allow-extra-groups resource claim says otherwise.
        // This driver sets neither claim, so any group named here would be a
        // group the workload does not have, and the boundary would refuse to
        // attach. Resolving the image's groups and then declaring them would
        // describe a process that does not exist.
        supplementary_gids: Vec::new(),
        uid,
        gid,
        source: source.to_string(),
        resource_digest: resource_digest.to_string(),
    })
}

// --- TLS material ------------------------------------------------------------

/// Generation-pinned TLS material for one boundary.
pub struct SandboxTlsMaterial {
    pub server_name: String,
    pub trust_anchor_pem: String,
    pub certificate_chain_pem: String,
    pub private_key_pem: String,
}

/// Generates the per-session TLS identity the boundary listener presents.
///
/// Mirrors upstream's `generate_sandbox_tls_material`: a self-signed session CA
/// issues one server certificate for the deterministic session name, so the
/// companion pins exactly this generation. The validity window matches
/// upstream's; the session is bounded by the sandbox's lifetime, not the
/// certificate's.
pub fn generate_sandbox_tls_material(session_id: &str) -> Result<SandboxTlsMaterial, DriverError> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let tls_err = |what: &str, e: rcgen::Error| DriverError::Internal(format!("{what}: {e}"));

    let server_name = format!("sandbox.{session_id}.openshell.internal");

    let ca_key =
        KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|e| tls_err("generate CA key", e))?;
    let mut ca_params = CertificateParams::default();
    ca_params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell sandbox session CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params
        .self_signed(&ca_key)
        .map_err(|e| tls_err("generate CA certificate", e))?;

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| tls_err("generate boundary TLS server key", e))?;
    let mut server_params = CertificateParams::new(vec![server_name.clone()])
        .map_err(|e| tls_err("build boundary certificate", e))?;
    server_params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    server_params.not_after = rcgen::date_time_ymd(4096, 1, 1);
    server_params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell sandbox runtime");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .map_err(|e| tls_err("sign boundary TLS server certificate", e))?;

    Ok(SandboxTlsMaterial {
        server_name,
        trust_anchor_pem: ca.pem(),
        certificate_chain_pem: server.pem(),
        private_key_pem: server_key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_authentication_json() -> Vec<u8> {
        serde_json::json!({
            "supervisor": {
                "session_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                "runtime_generation": "g0000000000000007",
                "session_rotation": 1,
                "auth_epoch": 1,
                "gateway_token": "header.payload.signature",
                "gateway_expires_at": 1_800_000_000_i64,
                "sandbox_token": "header.payload.signature",
                "sandbox_expires_at": 1_800_000_000_i64,
            },
            "gateway_id": "openshell-test",
            "verification_keys": [{
                "key_id": "openshell-test",
                "public_key_pem": Vec::from("-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n"),
            }],
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn launch_authentication_is_split_not_invented() {
        let auth = LaunchAuthentication::decode(&launch_authentication_json()).unwrap();
        assert_eq!(auth.view.session_id, "3f2504e0-4f89-11d3-9a0c-0305e82c3301");
        assert_eq!(auth.view.runtime_generation, "g0000000000000007");
        assert_eq!(auth.gateway_id, "openshell-test");

        // The companion's bundle is the gateway's, unchanged: the bearer
        // tokens and their real expiries survive the round trip.
        let bundle: serde_json::Value =
            serde_json::from_slice(&auth.supervisor_bundle().unwrap()).unwrap();
        assert_eq!(bundle["sandbox_token"], "header.payload.signature");
        assert_eq!(bundle["gateway_expires_at"], 1_800_000_000_i64);
    }

    #[test]
    fn verification_keys_become_utf8_pem_for_the_workload() {
        let auth = LaunchAuthentication::decode(&launch_authentication_json()).unwrap();
        let keys = auth.gateway_verification_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "openshell-test");
        assert!(keys[0]
            .public_key_pem
            .starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn missing_launch_authentication_is_rejected() {
        let err = LaunchAuthentication::decode(&[]).unwrap_err();
        assert!(matches!(err, DriverError::InvalidArgument(_)));
    }

    #[test]
    fn tls_material_pins_the_session_name() {
        let tls = generate_sandbox_tls_material("3f2504e0-4f89-11d3-9a0c-0305e82c3301").unwrap();
        assert_eq!(
            tls.server_name,
            "sandbox.3f2504e0-4f89-11d3-9a0c-0305e82c3301.openshell.internal"
        );
        assert!(tls
            .trust_anchor_pem
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(tls
            .certificate_chain_pem
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(tls.private_key_pem.contains("PRIVATE KEY"));
    }

    const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\nsandbox:x:1000:1000::/sandbox:/bin/sh\nother:x:1001:1001::/home/other:/bin/sh\n";
    const GROUP: &[u8] = b"root:x:0:\nsandbox:x:1000:\nextra:x:2000:sandbox\nempty:x:2001:\n";

    #[test]
    fn identity_defaults_to_the_image_sandbox_account() {
        let id = resolve_workload_identity("", "", PASSWD, GROUP, "sha256:abc").unwrap();
        assert_eq!((id.uid, id.gid), (1000, 1000));
        assert_eq!(id.source, "image");
    }

    /// The boundary's own privilege drop clears the supplementary set and
    /// then requires what it is running as to equal what was declared, so
    /// declaring the image's groups would make every sandbox refuse to
    /// attach. `extra` lists `sandbox` in [`GROUP`] and still must not
    /// appear.
    #[test]
    fn no_supplementary_groups_are_declared() {
        for (user, group) in [("", ""), ("sandbox", ""), ("other", "extra")] {
            let id = resolve_workload_identity(user, group, PASSWD, GROUP, "sha256:abc").unwrap();
            assert!(
                id.supplementary_gids.is_empty(),
                "{user:?}/{group:?} declared {:?}",
                id.supplementary_gids
            );
        }
    }

    #[test]
    fn requested_identity_overrides_the_image_default() {
        let id = resolve_workload_identity("other", "", PASSWD, GROUP, "sha256:abc").unwrap();
        assert_eq!((id.uid, id.gid), (1001, 1001));
        assert_eq!(id.source, "policy");
        assert!(id.supplementary_gids.is_empty());
    }

    #[test]
    fn numeric_selectors_resolve_without_a_passwd_entry() {
        let id = resolve_workload_identity("1500", "1600", PASSWD, GROUP, "sha256:abc").unwrap();
        assert_eq!((id.uid, id.gid), (1500, 1600));
    }

    #[test]
    fn root_is_rejected() {
        let err = resolve_workload_identity("root", "", PASSWD, GROUP, "sha256:abc").unwrap_err();
        assert!(format!("{err}").contains("unprivileged"), "{err}");
    }

    #[test]
    fn an_image_without_the_conventional_account_is_a_clear_error() {
        let err = resolve_workload_identity("", "", b"root:x:0:0::/root:/bin/sh\n", GROUP, "d")
            .unwrap_err();
        assert!(
            format!("{err}").contains("not present in the pinned image"),
            "{err}"
        );
    }

    fn fenced_evidence() -> LxdFenceEvidence {
        LxdFenceEvidence {
            instance_name: "test-sb".to_string(),
            network: "sandboxes".to_string(),
            network_type: "ovn".to_string(),
            egress_acl: "openshell-egress-sandboxes".to_string(),
            unexpected_networks: vec![],
        }
    }

    /// Without the ACL there is no default deny, and upstream requires every
    /// guarantee, so the driver has to refuse rather than attest three of four.
    #[test]
    fn a_sandbox_without_an_egress_acl_cannot_be_fenced() {
        let mut evidence = fenced_evidence();
        evidence.egress_acl = String::new();
        let err = evidence.project("g1").unwrap_err();
        assert!(format!("{err}").contains("OVN network"), "{err}");
    }

    /// A second NIC is an egress path the driver's ACL does not cover.
    #[test]
    fn a_second_network_cannot_be_fenced() {
        let mut evidence = fenced_evidence();
        evidence.unexpected_networks = vec!["lxdbr0".to_string()];
        assert!(evidence.project("g1").is_err());
    }

    /// The digest binds the projection to what was observed, so two sandboxes
    /// that differ only in what the driver saw cannot share a fence.
    #[test]
    fn the_evidence_digest_binds_the_observations() {
        let mut other = fenced_evidence();
        other.instance_name = "other-sb".to_string();
        assert_ne!(
            fenced_evidence().project("g1").unwrap().evidence_digest,
            other.project("g1").unwrap().evidence_digest
        );
    }

    /// ...and to the generation, so a fence cannot be replayed onto a later
    /// launch of the same sandbox.
    #[test]
    fn the_evidence_digest_binds_the_generation() {
        assert_ne!(
            fenced_evidence().project("g1").unwrap().evidence_digest,
            fenced_evidence().project("g2").unwrap().evidence_digest
        );
    }

    /// Upstream's own binding, computed by hand: the generation length as a
    /// big-endian u64, the generation, then the evidence.
    #[test]
    fn the_evidence_digest_matches_upstreams_binding() {
        use sha2::{Digest as _, Sha256};

        let evidence = fenced_evidence();
        let native = serde_json::to_vec(&evidence).unwrap();
        let mut binding = Vec::new();
        binding.extend_from_slice(&7_u64.to_be_bytes());
        binding.extend_from_slice(b"gen-abc");
        binding.extend_from_slice(&native);
        let expected: String = Sha256::digest(&binding)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(
            evidence.project("gen-abc").unwrap().evidence_digest,
            expected
        );
        assert_eq!(expected.len(), 64);
    }

    /// Upstream validates these on both sides and fails closed, so a claim it
    /// would reject has to be caught while there is still a request to fail.
    #[test]
    fn resource_claims_are_validated_the_way_upstream_validates_them() {
        for claims in [
            BTreeMap::from([("lxd.project".to_string(), String::new())]),
            BTreeMap::from([("lxd.image_alias".to_string(), "two words".to_string())]),
            BTreeMap::from([(String::new(), "value".to_string())]),
        ] {
            assert!(validate_resource_claims(&claims).is_err(), "{claims:?}");
        }
        assert!(validate_resource_claims(&BTreeMap::from([
            ("lxd.instance_name".to_string(), "sb-1".to_string()),
            ("lxd.project".to_string(), "default".to_string()),
        ]))
        .is_ok());
    }

    #[test]
    fn descriptor_serializes_in_the_upstream_shape() {
        let identity = ResolvedWorkloadIdentity {
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![],
            source: "image".to_string(),
            resource_digest: "sha256:abc".to_string(),
        };
        let fence = LxdFenceEvidence {
            instance_name: "test-sb".to_string(),
            network: "sandboxes".to_string(),
            network_type: "ovn".to_string(),
            egress_acl: "openshell-egress-sandboxes".to_string(),
            unexpected_networks: vec![],
        }
        .project("g0000000000000007")
        .expect("a fenced sandbox projects every guarantee");
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: "test-sb".to_string(),
            generation: "g0000000000000007".to_string(),
            session_id: "3f2504e0-4f89-11d3-9a0c-0305e82c3301".to_string(),
            workload_identity: identity,
            transport: SandboxTransport::Tcp {
                authority: format!("test-sb:{BOUNDARY_PORT}"),
                addresses: vec!["10.146.74.5:50051".parse().unwrap()],
            },
            tls: SandboxTlsClientConfig {
                server_name: "sandbox.x.openshell.internal".to_string(),
                trust_anchor_pem: "pem".to_string(),
            },
            host_gateway_ip: None,
            resource_claims: BTreeMap::from([(
                "lxd.instance_name".to_string(),
                "test-sb".to_string(),
            )]),
            outer_fence: fence,
        };
        let json = serde_json::to_value(&descriptor).unwrap();
        // Tagged enums carry upstream's discriminators, and nothing else.
        assert_eq!(json["transport"]["kind"], "tcp");
        assert_eq!(json["transport"]["addresses"][0], "10.146.74.5:50051");
        assert_eq!(
            json["outer_fence"]["established"],
            serde_json::json!([
                "default_deny_egress",
                "no_unmanaged_egress_path",
                "revocation_verified",
                "controller_loss_fails_closed",
            ])
        );
        assert_eq!(json["outer_fence"]["generation"], "g0000000000000007");
        assert_eq!(json["workload_identity"]["uid"], 1000);
        assert!(json["host_gateway_ip"].is_null());
    }
}
