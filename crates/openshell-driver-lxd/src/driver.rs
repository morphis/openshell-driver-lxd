// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core LXD compute driver logic, independent of the gRPC transport.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use computev1::pb::{
    CpuResourceCapabilities, DriverSandbox, DriverSandboxSpec, GetCapabilitiesResponse,
    GpuResourceCapabilities, MemoryResourceCapabilities, ResourceCapabilities,
};
use lxd_client::{LxdClient, LxdError, NetworkType};
use tokio::sync::{Mutex, OnceCell, RwLock};

use crate::admission::DriverAdmissionConfig;
use crate::config::Config;
use crate::dhcp_client;
use crate::error::DriverError;
use crate::image::{self, digest_of_file, ImageCache, SkopeoImporter};
use crate::isolation;
use crate::mapping;
use crate::protocol;

const DRIVER_NAME: &str = "lxd";

/// How long to wait for a started workload to acquire the IPv4 address its
/// supervisor companion dials. DHCP runs inside the container, after start.
const BOUNDARY_ADDRESS_TIMEOUT_SECS: u64 = 60;

/// How long to let a freshly started sandbox settle before checking that its
/// init is still up. See [`LxdComputeDriver::settle_after_start`].
const SETTLE_DELAY: Duration = Duration::from_secs(3);

/// How long LXD may take to clear `volatile.last_state.power` after a
/// sandbox's init exits, before that key can be read as "LXD stopped it".
///
/// LXD writes the key when the instance starts and rewrites it as part of
/// finishing the stop, so an init that exited by itself reads as stopped but
/// still `RUNNING` until then. Measured at 0.62–0.75s over 20 stops on LXD
/// 6.9; three times the longest leaves room on a loaded host.
/// See [`LxdComputeDriver::confirm_runtime_restart`].
const RUNTIME_RESTART_SETTLE: Duration = Duration::from_millis(2250);

/// How many times a create is retried through LXD's own ACL setup race.
///
/// More than one attempt can lose: the two instances racing can fail at
/// different points of LXD's NIC attach, and the loser of one can go on to
/// lose the other.
const ACL_SETUP_RETRIES: u32 = 8;

/// How long to wait between those attempts. The loser of the race only has to
/// wait for the winner's OVN transaction, which is quick.
const ACL_SETUP_RETRY_DELAY: Duration = Duration::from_millis(500);

/// LXD's own sentences for the two places it sets a NIC's ACLs up in OVN.
///
/// Both are reached while attaching the NIC during instance creation, and both
/// fail when another instance creation is doing the same thing at the same
/// time — `ovn-nbctl` has been observed rejecting the second transaction and
/// also aborting outright (`signal: aborted (core dumped)`) on MicroOVN 24.03.
const ACL_SETUP_FAILURES: &[&str] = &[
    "Failed ensuring security ACLs are configured in OVN",
    "Failed applying OVN default ACL rules for instance NIC",
];

/// Whether `error` is LXD failing to set a NIC's ACLs up in OVN because
/// another instance creation was doing the same thing.
///
/// Matched on the text because that is all LXD gives: the REST API reports it
/// as a generic operation failure carrying `ovn-nbctl`'s output. Only LXD's
/// own sentences are matched, not `ovn-nbctl`'s — one race was observed
/// reported three ways on one host (a uniqueness constraint violation,
/// "multiple rows in Port_Group match", and a core dump), so keying on the
/// tail would catch it only sometimes.
fn is_acl_setup_race(error: &DriverError) -> bool {
    let DriverError::Lxd(error) = error else {
        return false;
    };
    let message = error.to_string();
    ACL_SETUP_FAILURES
        .iter()
        .any(|failure| message.contains(failure))
}

/// The two ACLs one sandbox owns.
///
/// `protocol` is carried by both halves and is the whole of what the workload
/// is allowed: inbound Sandbox Protocol and, with the NIC defaults at
/// `reject`, nothing outbound at all. `egress` is carried by the companion
/// alone and holds what only it may do.
struct SandboxAcls {
    protocol: String,
    egress: String,
}

/// Returns true if `err` indicates the instance was already stopped.
///
/// Covers both cases: LXD rejects the stop request synchronously with a
/// 400, or accepts it and the operation fails asynchronously once it
/// discovers the instance already reached the target state.
fn is_already_stopped(err: &LxdError) -> bool {
    let message = match err {
        LxdError::Api {
            status_code: 400,
            message,
        } => message,
        LxdError::OperationFailed { err, .. } => err,
        LxdError::Api { .. }
        | LxdError::InvalidQuantity { .. }
        | LxdError::Io(_)
        | LxdError::Hyper(_)
        | LxdError::Http(_)
        | LxdError::Json(_)
        | LxdError::Tls { .. }
        | LxdError::WebSocket { .. } => return false,
    };
    message.contains("not running") || message.contains("already stopped")
}

/// LXD compute driver.
#[derive(Debug, Clone)]
pub struct LxdComputeDriver {
    config: Config,
    lxd: LxdClient,
    image_cache: ImageCache,
    supervisor_volume_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    dhcp_client_volume_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    lifecycle_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    /// Held shared from provisioning a sandbox's auxiliary volumes until its
    /// instance uses them, and exclusively by clean-up, which would otherwise
    /// see those volumes unused and remove them.
    volume_use: Arc<RwLock<()>>,
    /// Where sandboxes land absent a per-request choice, resolved once from
    /// the project's `default` profile. See [`Self::placement_defaults`].
    placement_defaults: Arc<OnceCell<mapping::PlacementDefaults>>,
}

impl LxdComputeDriver {
    #[must_use]
    pub fn new(config: Config, lxd: LxdClient) -> Self {
        let importer = Arc::new(SkopeoImporter::new(
            lxd.clone(),
            config.skopeo_path.clone(),
            config.umoci_path.clone(),
            config.mksquashfs_path.clone(),
            config.image_work_dir.clone(),
            Duration::from_secs(config.image_pull_timeout_secs),
            Duration::from_secs(config.image_convert_timeout_secs),
        ));
        let image_cache = ImageCache::new(
            lxd.clone(),
            importer,
            config.image_cache_alias_prefix.clone(),
        );
        Self::with_image_cache(config, lxd, image_cache)
    }

    #[must_use]
    pub fn with_image_cache(config: Config, lxd: LxdClient, image_cache: ImageCache) -> Self {
        Self {
            config,
            lxd,
            image_cache,
            supervisor_volume_locks: Arc::new(Mutex::new(HashMap::new())),
            dhcp_client_volume_locks: Arc::new(Mutex::new(HashMap::new())),
            lifecycle_locks: Arc::new(Mutex::new(HashMap::new())),
            volume_use: Arc::new(RwLock::new(())),
            placement_defaults: Arc::new(OnceCell::new()),
        }
    }

    /// Where sandboxes land when their request names neither a network nor a
    /// storage pool: the operator's `--default-network`/`--default-storage-pool`
    /// when given, otherwise the project's `default` profile.
    ///
    /// Resolved on first use and then cached, so a driver given nothing but
    /// `--project` reads the project's layout once rather than on every
    /// create. A project is not re-laid-out under a running driver; restart it
    /// if the profile changes.
    pub async fn placement_defaults(&self) -> Result<&mapping::PlacementDefaults, DriverError> {
        self.placement_defaults
            .get_or_try_init(|| async {
                let profile = self.lxd.get_profile(mapping::DEFAULT_PROFILE).await?;
                let defaults = mapping::PlacementDefaults::resolve(
                    &self.config.project,
                    &profile,
                    self.config.default_network.as_deref(),
                    self.config.default_storage_pool.as_deref(),
                )?;
                tracing::info!(
                    project = %self.config.project,
                    network = %defaults.network,
                    storage_pool = %defaults.storage_pool,
                    "resolved default sandbox placement"
                );
                Ok(defaults)
            })
            .await
    }

    /// Best-effort pre-warm of the default sandbox image so the first
    /// `create_sandbox` need not block on a registry pull, and so a bad
    /// default reference or an unreachable registry surfaces at startup
    /// rather than on the first request. Importing requires the external
    /// tooling (skopeo/umoci/mksquashfs); any failure here is logged and
    /// otherwise ignored — the same import is retried on first use.
    pub async fn ensure_default_image(&self) -> Result<String, DriverError> {
        self.resolve_image(&self.config.default_image).await
    }

    /// Resolves `reference` to a local LXD image alias, refusing a registry
    /// the operator has not allowed.
    ///
    /// Every image the driver pulls goes through here, the request's own
    /// `template.image` above all: without a check a sandbox request reaches
    /// whatever registry the gateway pod's network reaches.
    async fn resolve_image(&self, reference: &str) -> Result<String, DriverError> {
        image::check_registry_allowed(reference, &self.config.allowed_registries)?;
        self.image_cache.resolve_alias(reference).await
    }

    /// The supervisor binary on the host and its digest, extracting it from
    /// the sandbox binary image on first use.
    async fn resolve_supervisor(&self) -> Result<(std::path::PathBuf, String), DriverError> {
        let binary_path = self
            .config
            .sandbox_bin
            .as_ref()
            .or(self.config.supervisor_bin.as_ref());
        match binary_path {
            Some(path) => Ok((path.clone(), digest_of_file(path)?)),
            None => self.extract_sandbox_binary().await.map_err(|e| {
                DriverError::ImageImport(format!("sandbox binary extraction failed: {e}"))
            }),
        }
    }

    /// Extracts the in-workload boundary binary from the configured image,
    /// refusing a registry the operator has not allowed.
    async fn extract_sandbox_binary(&self) -> Result<(std::path::PathBuf, String), DriverError> {
        image::check_registry_allowed(
            &self.config.sandbox_binary_image,
            &self.config.allowed_registries,
        )?;
        self.image_cache
            .extract_supervisor_binary(
                &self.config.sandbox_binary_image,
                &self.config.supervisor_cache_dir,
            )
            .await
    }

    /// Removes images, volumes and host files the driver no longer uses (see
    /// `crate::gc`). Best-effort: failures are logged and retried on the
    /// next run.
    pub async fn collect_garbage(&self) {
        // Without the current supervisor digest nothing supervisor-related
        // can be told apart from what is in use, so those are left alone.
        let supervisor_digest = match self.resolve_supervisor().await {
            Ok((_, digest)) => Some(digest),
            Err(e) => {
                tracing::warn!(%e, "could not resolve the supervisor; keeping its volumes and cache");
                None
            }
        };

        // Likewise for the DHCP client: it is resolved from the host, so
        // without its digest the volume in use cannot be told from a stale one.
        let dhcp_digest =
            match dhcp_client::load_guest_net_tools(self.config.dhcp_client_bin.as_deref()).await {
                Ok(tools) => Some(tools.digest),
                Err(e) => {
                    tracing::warn!(%e, "could not resolve the DHCP client; keeping its volumes");
                    None
                }
            };

        // The default image is resolved by every create that names no image of
        // its own, so it is never collected however long it has sat unused.
        // Without knowing which image that is, nothing is collected by age:
        // the one image that must survive is exactly the one that cannot be
        // identified.
        //
        // The supervisor image is kept for the same reason and was not: it is
        // converted and cached under the same scheme as any other, but no
        // create refreshes its `last_used_at` unless a sandbox happens to be
        // made from it, so a week of idleness had the collector evict the one
        // image every sandbox's trusted half comes from — leaving the next
        // create to re-import it, and to need the registry to be reachable to
        // do so.
        let mut keep_aliases: Vec<String> = Vec::new();
        let mut unresolved = false;
        for image in [&self.config.default_image, &self.config.supervisor_image] {
            match self.cache_alias_to_keep(image).await {
                Some(alias) => keep_aliases.push(alias),
                None => unresolved = true,
            }
        }
        if unresolved {
            keep_aliases.clear();
        }
        let images = crate::gc::ImageRetention {
            retention: if keep_aliases.is_empty() {
                Duration::ZERO
            } else {
                Duration::from_secs(self.config.image_retention_secs)
            },
            keep_aliases: &keep_aliases,
        };

        let volume_use = self.volume_use.write().await;
        let lxd = match (&supervisor_digest, &dhcp_digest) {
            (Some(supervisor), Some(dhcp)) => {
                let keep = vec![
                    mapping::supervisor_volume_name(supervisor),
                    mapping::dhcp_client_volume_name(dhcp),
                ];
                crate::gc::collect_lxd(
                    &self.lxd,
                    &self.config.image_cache_alias_prefix,
                    &keep,
                    images,
                )
                .await
            }
            // Keep every auxiliary volume by treating none as removable.
            _ => {
                crate::gc::collect_lxd_images_only(
                    &self.lxd,
                    &self.config.image_cache_alias_prefix,
                    images,
                )
                .await
            }
        };
        drop(volume_use);

        let host_entries = crate::gc::collect_host(
            &self.config.supervisor_cache_dir,
            if self.config.supervisor_bin.is_some() {
                None
            } else {
                supervisor_digest.as_deref()
            },
            &self.config.image_work_dir,
            std::time::SystemTime::now(),
        );

        tracing::debug!(
            images = lxd.images,
            volumes = lxd.volumes,
            acls = lxd.acls,
            host_entries,
            "clean-up finished"
        );
    }

    /// The cache alias for an image the driver needs on every create, or
    /// `None` if it cannot be worked out.
    ///
    /// `None` is what stops the collector: an image that cannot be named
    /// cannot be exempted, and collecting by age without knowing which images
    /// must survive would evict exactly the one that must not.
    async fn cache_alias_to_keep(&self, image: &str) -> Option<String> {
        match self.image_cache.cache_alias_for(image).await {
            Ok(alias) => Some(alias),
            Err(e) => {
                tracing::warn!(
                    %image,
                    %e,
                    "could not resolve an image the driver always needs; \
                     not collecting any image this run"
                );
                None
            }
        }
    }

    /// Clone of the LXD client, for the lifecycle watcher.
    #[must_use]
    pub fn lxd_client(&self) -> LxdClient {
        self.lxd.clone()
    }

    /// Report driver capabilities and defaults.
    #[must_use]
    pub fn capabilities(&self) -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            driver_name: DRIVER_NAME.to_string(),
            // Kept for diagnostics only; the gateway reads the version from
            // `extension` below.
            driver_version: env!("CARGO_PKG_VERSION").to_string(),
            default_image: self.config.default_image.clone(),
            // The gateway would stop every sandbox when it shuts down and
            // start them again when it comes back. Sandboxes keep running
            // across gateway restarts instead; StartSandbox is only for
            // sandboxes that were stopped.
            gateway_manages_lifecycle: false,
            // Sandboxes get their gateway credentials from the driver; there
            // is no platform credential for AuthenticateSandbox to verify, so
            // there is no runtime identity for the gateway to bind either.
            supports_sandbox_authentication: false,
            // The sandbox's own supervisor session is what readiness means
            // here, as for every driver that runs the standard supervisor.
            driver_reports_runtime_readiness: false,
            resource_capabilities: Some(ResourceCapabilities {
                cpu: Some(CpuResourceCapabilities {
                    limit_supported: true,
                }),
                memory: Some(MemoryResourceCapabilities {
                    limit_supported: true,
                }),
                gpu: Some(GpuResourceCapabilities {
                    // A GPU request attaches the host's GPUs through an LXD
                    // `gputype: physical` device.
                    default_selection_supported: true,
                    // Honoring a count needs host GPU inventory the driver
                    // does not collect; see `create_sandbox`.
                    count_selection_supported: false,
                }),
            }),
            // The driver takes images from a registry, not from a rootfs tar
            // staged by the gateway. Zero tells the gateway not to offer one.
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
            extension: Some(protocol::driver_metadata()),
            // Byte-for-byte what the gateway computes from its own
            // `[openshell.drivers.<name>]` configuration, or it refuses to
            // provision through this driver at all. See `crate::admission`.
            resource_admission_policy: self.admission_policy().acknowledgement(),
        }
    }

    /// The admission policy this driver enforces and acknowledges.
    #[must_use]
    pub fn admission_policy(&self) -> DriverAdmissionConfig {
        DriverAdmissionConfig {
            allow_driver_config: self.config.allow_driver_config,
            resource_admission: self.config.resource_admission(),
        }
    }

    pub async fn validate_sandbox_create(
        &self,
        sandbox: &DriverSandbox,
    ) -> Result<(), DriverError> {
        if sandbox.name.is_empty() {
            return Err(DriverError::InvalidArgument(
                "sandbox.name is required".into(),
            ));
        }
        if sandbox.id.is_empty() {
            return Err(DriverError::InvalidArgument(
                "sandbox.id is required".into(),
            ));
        }
        // The name becomes an LXD instance name and is interpolated into the
        // REST paths the client builds, so it has to be one before it goes
        // anywhere near either.
        if !mapping::is_valid_instance_name(&sandbox.name) {
            return Err(DriverError::InvalidArgument(format!(
                "sandbox.name {:?} is not a usable LXD instance name: 1-{} characters, \
                 ASCII letters, digits and dashes, starting with a letter",
                sandbox.name,
                mapping::MAX_SANDBOX_NAME_LEN
            )));
        }
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| DriverError::InvalidArgument("sandbox.spec is required".into()))?;
        let template = spec.template.as_ref().ok_or_else(|| {
            DriverError::InvalidArgument("sandbox.spec.template is required".into())
        })?;

        // The gateway rejects caller driver config before it gets here when
        // the policy forbids it, but a driver socket has other callers, and
        // the policy this driver acknowledged is the one it must enforce.
        if !self.config.allow_driver_config
            && template
                .driver_config
                .as_ref()
                .is_some_and(|config| !config.fields.is_empty())
        {
            return Err(DriverError::FailedPrecondition(
                "caller driver config is disabled; start the driver with \
                 --allow-driver-config and set allow_driver_config = true for this driver in \
                 the gateway's configuration"
                    .into(),
            ));
        }

        // `user_namespaces` is a portable intent each driver maps to its own
        // platform. An LXD container is unprivileged, and therefore user-
        // namespaced, unless it is explicitly made privileged — so `true` and
        // "unset" are both already true here. `false` asks for a privileged
        // container, which would hand the workload host-uid semantics; refuse
        // rather than quietly provide the opposite of what was asked for.
        if template.user_namespaces == Some(false) {
            return Err(DriverError::InvalidArgument(
                "user_namespaces = false asks for a sandbox outside a user namespace, which on \
                 LXD means a privileged container; this driver does not provision one"
                    .into(),
            ));
        }

        // An empty image means the default image, which is validated when it
        // is resolved.
        if !template.image.is_empty() {
            image::validate_reference(&template.image)?;
        }

        for key in template.labels.keys() {
            if !mapping::is_valid_label_key(key) {
                return Err(DriverError::InvalidArgument(format!(
                    "invalid label key {key:?}: must match [a-zA-Z0-9._-]+"
                )));
            }
        }

        if let Some(count) = spec
            .resource_requirements
            .as_ref()
            .and_then(|r| r.gpu.as_ref())
            .and_then(|g| g.count)
        {
            if count == 0 {
                return Err(DriverError::InvalidArgument(
                    "sandbox.spec.resource_requirements.gpu.count must be at least 1 if set; \
                     omit it to request the default GPU assignment"
                        .into(),
                ));
            }
        }

        // A profile contributes config and devices to the instance, and the
        // instance is the untrusted half of the sandbox. Several profile keys
        // would undo it outright: `environment.OPENSHELL_ROLE=supervisor`
        // flips the *workload's* init into the branch that runs the
        // supervisor image's own programs as root; `raw.lxc` can add an
        // interface the fence evidence never sees, drop the AppArmor profile
        // or replace the init command; `raw.idmap` maps a host uid into the
        // container; `security.*` owns the user namespace, the syscall
        // interceptions and the guest API. A profile may still *place* an
        // instance; it may not reconfigure what the instance is.
        //
        // This is a denylist by prefix rather than by key, because the keys
        // that matter share prefixes and new ones keep arriving; anything the
        // driver does not recognise under those prefixes is refused rather
        // than admitted. `security.privileged` and `security.nesting` are
        // also pinned on the instance itself, which overrides any profile —
        // including `default`, which a caller does not name and the driver
        // cannot refuse.
        for name in mapping::build_profiles(template) {
            // Fails closed. A profile that cannot be read is a profile whose
            // contents are unknown, and admitting it on a transient LXD error
            // would make the whole check something an attacker can wait out.
            // A profile that does not exist fails the create a moment later
            // anyway, so nothing legitimate is lost by refusing here.
            let profile = self.lxd.get_profile(&name).await.map_err(|e| {
                DriverError::FailedPrecondition(format!(
                    "profile {name:?} could not be read, so what it would add to the sandbox \
                     is unknown: {e}"
                ))
            })?;
            for key in profile.config.keys() {
                if key.starts_with("environment.OPENSHELL_")
                    || key.starts_with("raw.")
                    || key.starts_with("security.")
                    || key == "linux.kernel_modules"
                {
                    return Err(DriverError::FailedPrecondition(format!(
                        "profile {name:?} sets {key:?}, which a sandbox's own configuration owns"
                    )));
                }
            }

            // `default` is exempt from the device check, and only from this
            // one: every instance in the project gets it, it is where a
            // deployment puts its root disk and its network, and refusing it
            // would refuse every sandbox. What it can add is bounded by the
            // instance's own devices, which take precedence by name, and by
            // the fence evidence, which reads every NIC and proxy device off
            // the created instance whatever put it there.
            if name == "default" {
                continue;
            }
            for (device, properties) in &profile.devices {
                let kind = properties.get("type").map(String::as_str).unwrap_or("");
                // An allowlist: a placement profile names a pool for the root
                // disk, and that is all it needs to do. Everything else is
                // either an egress path the fence does not cover (`nic`,
                // `proxy`, `infiniband`) or a piece of the host handed to the
                // untrusted half (`disk` with a `source`, `unix-char`,
                // `unix-block`, `usb`, `pci`, `gpu`, `tpm`) — including a
                // `disk` mounted over `/opt/openshell`, which would shadow
                // the volumes every program on the workload's boot path comes
                // from.
                let placement_only = kind == "disk" && !properties.contains_key("source");
                if !placement_only {
                    return Err(DriverError::FailedPrecondition(format!(
                        "profile {name:?} adds a {kind} device {device:?}; a profile may say \
                         where a sandbox lands, but what it is attached to and what of the \
                         host it can reach are the driver's to decide"
                    )));
                }
            }
        }

        // The companion this sandbox would get is named after it, and a
        // sandbox may already be called that: names come from the gateway,
        // which passes the user's own. Refusing here says so plainly, rather
        // than leaving a create to fail half way through on a name LXD
        // reports only as taken.
        let sup_name = mapping::supervisor_instance_name(&sandbox.name);
        if let Ok(existing) = self.lxd.get_instance(&sup_name).await {
            if !mapping::is_companion_of(&existing, &sandbox.name, None) {
                return Err(DriverError::FailedPrecondition(format!(
                    "instance {sup_name:?} already exists and is not this sandbox's \
                     supervisor companion, which is what this sandbox's companion would \
                     have to be called; rename the sandbox or remove {sup_name:?}"
                )));
            }
        }

        Ok(())
    }

    /// Refuses a sandbox whose recorded driver config the policy no longer
    /// allows.
    ///
    /// `allow_driver_config` gates `network`, `storage_pool`, `profiles` and
    /// `max_processes`, so a sandbox created while it was on is running with
    /// choices the operator has since withdrawn. Checking the flag alone at
    /// start would say nothing about that — the flag describes what may be
    /// asked for now, the record describes what this sandbox already has.
    ///
    /// Mirrors upstream's `check_config_provenance`, including its treatment
    /// of a missing record: a sandbox that cannot say how it was created
    /// cannot be admitted, so one from a build that did not record it has to
    /// be recreated. Upstream's Podman and Docker drivers fail closed the
    /// same way.
    fn check_config_provenance(&self, instance: &lxd_client::Instance) -> Result<(), DriverError> {
        let recorded = instance
            .config
            .get(mapping::KEY_CALLER_DRIVER_CONFIG)
            .map(String::as_str);
        match recorded {
            Some("false") => Ok(()),
            Some("true") if self.config.allow_driver_config => Ok(()),
            Some("true") => Err(DriverError::FailedPrecondition(
                "this sandbox was created with caller driver config, which is now disabled; \
                 re-enable --allow-driver-config, or delete the sandbox and create it again \
                 without it"
                    .into(),
            )),
            _ => Err(DriverError::FailedPrecondition(
                "this sandbox does not record whether it was created with caller driver \
                 config, so it cannot be admitted; delete it and create it again"
                    .into(),
            )),
        }
    }

    /// Waits for an LXD operation to complete, bounded by
    /// `Config::operation_timeout_secs` so a hung LXD instance cannot block
    /// an RPC indefinitely.
    async fn wait_operation(&self, id: &str) -> Result<(), DriverError> {
        tokio::time::timeout(
            Duration::from_secs(self.config.operation_timeout_secs),
            self.lxd.wait_operation(id),
        )
        .await
        .map_err(|_| DriverError::Timeout)??;
        Ok(())
    }

    /// Fetches an instance by name and confirms it's driver-managed.
    ///
    /// Rejects arbitrary non-driver LXD instances as not found; "managed"
    /// means the instance carries the `user.openshell.sandbox_id` marker
    /// `create_sandbox` sets.
    async fn get_managed_instance(&self, name: &str) -> Result<lxd_client::Instance, DriverError> {
        let not_found = || DriverError::NotFound(format!("sandbox {name:?} not found"));
        let instance = match self.lxd.get_instance(name).await {
            Ok(instance) => instance,
            Err(LxdError::Api {
                status_code: 404, ..
            }) => return Err(not_found()),
            Err(e) => return Err(e.into()),
        };
        if !instance.config.contains_key(mapping::KEY_SANDBOX_ID)
            || instance.config.get(mapping::KEY_ROLE).map(String::as_str)
                == Some(mapping::ROLE_SUPERVISOR)
        {
            return Err(not_found());
        }
        Ok(instance)
    }

    pub async fn get_sandbox(&self, name: &str) -> Result<DriverSandbox, DriverError> {
        let instance = self.get_managed_instance(name).await?;
        let instance = self.confirm_runtime_restart(instance).await;
        let mut sandbox = mapping::instance_to_driver_sandbox(&instance);

        // Passed even when it is missing: a workload whose companion is gone
        // has no supervision, and saying so is the only way that shows up at
        // all — the companion is hidden from every other query.
        let companion = self
            .companion_of(
                name,
                instance
                    .config
                    .get(mapping::KEY_SANDBOX_ID)
                    .map(String::as_str),
            )
            .await;
        mapping::aggregate_companion_status(&mut sandbox, companion.as_ref());

        Ok(sandbox)
    }

    /// This sandbox's companion, if it exists and really is this sandbox's.
    ///
    /// Resolved by name and then checked, never by name alone: see
    /// [`mapping::is_companion_of`] for why the name is not enough. An
    /// instance of that name belonging to something else is reported as no
    /// companion at all, which is what it is as far as this sandbox goes.
    async fn companion_of(
        &self,
        name: &str,
        sandbox_id: Option<&str>,
    ) -> Option<lxd_client::Instance> {
        let sup_name = mapping::supervisor_instance_name(name);
        let instance = self.lxd.get_instance(&sup_name).await.ok()?;
        if mapping::is_companion_of(&instance, name, sandbox_id) {
            return Some(instance);
        }
        tracing::warn!(
            sandbox = %name,
            instance = %sup_name,
            "an instance holds this sandbox's companion name but is not its companion; \
             leaving it alone"
        );
        None
    }

    /// Deletes an instance and waits for the deletion to finish.
    ///
    /// Cleanup paths have to wait rather than fire and forget: an instance
    /// that still exists holds the sandbox's ACLs in LXD's `used_by`, and the
    /// `delete_sandbox_acl` that follows would be refused and leave them for
    /// the six-hourly collector. Best-effort, because the failure that
    /// brought us here is the one worth reporting.
    async fn delete_instance_and_wait(&self, name: &str) {
        match self.lxd.delete_instance(name).await {
            Ok(op) => {
                let _ = self.wait_operation(&op.id).await;
            }
            Err(e) => tracing::warn!(instance = %name, %e, "failed to delete instance"),
        }
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, DriverError> {
        let instances = self.lxd.list_instances().await?;
        let mut sandboxes: Vec<DriverSandbox> = Vec::new();
        let mut unsettled: Vec<usize> = Vec::new();
        for instance in instances.iter().filter(|i| {
            i.config.contains_key(mapping::KEY_SANDBOX_ID)
                && i.config.get(mapping::KEY_ROLE).map(String::as_str)
                    != Some(mapping::ROLE_SUPERVISOR)
        }) {
            if mapping::stopped_by_the_runtime(instance) {
                unsettled.push(sandboxes.len());
            }
            let mut sb = mapping::instance_to_driver_sandbox(instance);
            let sup_name = mapping::supervisor_instance_name(&instance.name);
            let companion = instances.iter().find(|i| {
                i.name == sup_name
                    && mapping::is_companion_of(
                        i,
                        &instance.name,
                        instance
                            .config
                            .get(mapping::KEY_SANDBOX_ID)
                            .map(String::as_str),
                    )
            });
            mapping::aggregate_companion_status(&mut sb, companion);
            sandboxes.push(sb);
        }

        // One wait covers every sandbox that looked stopped by LXD, so a list
        // costs at most a single settle however many of them there are.
        if !unsettled.is_empty() {
            tokio::time::sleep(RUNTIME_RESTART_SETTLE).await;
            for index in unsettled {
                let Ok(instance) = self.lxd.get_instance(&sandboxes[index].name).await else {
                    continue;
                };
                let mut sb = mapping::instance_to_driver_sandbox(&instance);
                let companion = self
                    .companion_of(
                        &instance.name,
                        instance
                            .config
                            .get(mapping::KEY_SANDBOX_ID)
                            .map(String::as_str),
                    )
                    .await;
                mapping::aggregate_companion_status(&mut sb, companion.as_ref());
                sandboxes[index] = sb;
            }
        }
        Ok(sandboxes)
    }

    /// Re-reads a sandbox that looks stopped by LXD itself, once the marker
    /// it is recognized by has had time to settle.
    ///
    /// `volatile.last_state.power` stays `RUNNING` for about a second after
    /// an init exits (see [`RUNTIME_RESTART_SETTLE`]), so reporting straight
    /// off the first read would call every sandbox that just died a runtime
    /// restart. A marker still set after the wait is a real one: LXD stopped
    /// the sandbox and has not brought it back.
    async fn confirm_runtime_restart(
        &self,
        instance: lxd_client::Instance,
    ) -> lxd_client::Instance {
        if !mapping::stopped_by_the_runtime(&instance) {
            return instance;
        }
        tokio::time::sleep(RUNTIME_RESTART_SETTLE).await;
        self.lxd
            .get_instance(&instance.name)
            .await
            .unwrap_or(instance)
    }

    /// Resolves an instance name from a gateway-assigned `sandbox_id` by
    /// scanning driver-managed instances for a config match. Used as a
    /// fallback when a request supplies only `sandbox_id`, not
    /// `sandbox_name` — LXD itself has no by-id lookup, only by-name.
    pub async fn find_name_by_sandbox_id(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<String>, DriverError> {
        let instances = self.lxd.list_instances().await?;
        Ok(instances
            .into_iter()
            .find(|i| {
                i.config.get(mapping::KEY_SANDBOX_ID).map(String::as_str) == Some(sandbox_id)
                    && i.config.get(mapping::KEY_ROLE).map(String::as_str)
                        != Some(mapping::ROLE_SUPERVISOR)
            })
            .map(|i| i.name))
    }

    pub async fn create_sandbox(&self, sandbox: &DriverSandbox) -> Result<(), DriverError> {
        self.validate_sandbox_create(sandbox).await?;

        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| DriverError::InvalidArgument("sandbox.spec is required".into()))?;
        let template = spec.template.as_ref().ok_or_else(|| {
            DriverError::InvalidArgument("sandbox.spec.template is required".into())
        })?;

        let defaults = self.placement_defaults().await?;
        let placement =
            mapping::Placement::resolve(template, &defaults.network, &defaults.storage_pool);
        let network = self.check_placement(placement).await?;

        let gateway_endpoint = self.resolve_gateway_endpoint(placement.network, &network)?;
        // Not optional since OpenShell v0.1.0: this ACL is the sandbox's outer
        // network fence, and both halves of a sandbox refuse to run without
        // one. See `isolation::LxdFenceEvidence::project`.
        let fence_acl = self
            .ensure_network_egress_acl(placement.network, &network)
            .await?;
        // RFC 0012: the gateway mints the credentials both halves authenticate
        // with. The driver splits them; it never invents them.
        let launch = isolation::LaunchAuthentication::decode(&spec.launch_authentication)?;

        let mut config = mapping::build_create_config(
            sandbox,
            spec,
            template,
            self.config.default_max_processes,
            &self.config.log_level,
        )?;

        if self.config.sandbox_nesting {
            config.insert("security.nesting".to_string(), "true".to_string());
        }

        config.insert(
            mapping::KEY_NETWORK.to_string(),
            placement.network.to_string(),
        );
        config.insert(
            mapping::KEY_EGRESS_ACL.to_string(),
            crate::egress::sandbox_protocol_acl_name(&sandbox.name),
        );
        config.insert(
            mapping::KEY_NETWORK_TYPE.to_string(),
            network.type_.to_string(),
        );

        // Auxiliary volumes live on the sandbox's own pool unless the
        // operator pinned them, so a request asking for a non-default
        // `storage_pool` does not end up with its rootfs on one pool and its
        // supervisor volume on another.
        let aux_pool = self
            .config
            .supervisor_storage_pool
            .as_deref()
            .unwrap_or(placement.storage_pool);

        let gpu = spec
            .resource_requirements
            .as_ref()
            .and_then(|r| r.gpu.as_ref());
        // v1: a GPU request attaches every physical GPU on the host (LXD's
        // default for a `gputype: physical` device with no selector on
        // containers); `count` would need host GPU inventory to honor
        // precisely and isn't consulted yet.
        if let Some(count) = gpu.and_then(|g| g.count) {
            tracing::debug!(
                count,
                "GpuResourceRequirements.count is ignored in v1; attaching all host GPUs"
            );
        }
        let (binary_path, digest) = self.resolve_supervisor().await?;

        // Resolved before the volumes are provisioned: an import can take
        // minutes, and clean-up waits while volumes are provisioned but unused.
        let image_alias = if template.image.is_empty() {
            self.resolve_image(&self.config.default_image).await?
        } else {
            self.resolve_image(&template.image).await?
        };

        config.insert(mapping::KEY_IMAGE_ALIAS.to_string(), image_alias.clone());
        let child_env = mapping::workload_child_env(spec, template);
        config.insert(
            mapping::KEY_CHILD_ENV.to_string(),
            serde_json::to_string(&child_env).map_err(|e| {
                DriverError::Internal(format!("serialize workload environment: {e}"))
            })?,
        );

        let supervisor_image_alias = self
            .image_cache
            .resolve_alias(&self.config.supervisor_image)
            .await?;

        let volume_use = self.volume_use.read().await;

        // ...and the ACL that is this sandbox's alone, carrying its gateway
        // and the Sandbox Protocol between its two halves.
        //
        // Created under `volume_use`, and not earlier, for the same reason the
        // auxiliary volumes are: clean-up removes a per-sandbox ACL that
        // nothing uses, and an ACL that has been created but not yet attached
        // to an instance is exactly that. Without the lock a clean-up landing
        // in the window between the two deletes the ACL the create is about to
        // name, and LXD rejects the instance with "Network ACL ... does not
        // exist". The window is small and the clean-up interval is long, which
        // is what makes this the kind of race that passes every test and then
        // fails a suite.
        let sandbox_acls = self
            .ensure_sandbox_acls(&sandbox.name, &gateway_endpoint)
            .await?;
        // The halves are not given the same thing. The workload carries only
        // the protocol ACL, so with both NIC defaults at `reject` it has no
        // egress at all — its traffic is relayed by the companion, and the
        // fence has to hold if the in-guest boundary is ever escaped. The
        // companion carries what it needs to do that relaying.
        let workload_acls = [sandbox_acls.protocol.as_str()];
        let companion_acls = [
            fence_acl.as_str(),
            sandbox_acls.protocol.as_str(),
            sandbox_acls.egress.as_str(),
        ];

        // Ensure digest-keyed custom storage volume exists on the aux pool.
        // Locks are keyed by pool *and* digest: the same binary on two pools
        // is two distinct volumes.
        let volume_name = mapping::supervisor_volume_name(&digest);
        let vol_lock = {
            let mut locks = self.supervisor_volume_locks.lock().await;
            locks
                .entry(format!("{aux_pool}/{digest}"))
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        {
            let _guard = vol_lock.lock().await;
            self.lxd
                .ensure_supervisor_volume(aux_pool, &volume_name, &binary_path)
                .await
                .map_err(|e| {
                    DriverError::ImageImport(format!(
                        "supervisor binary volume provisioning failed on pool {aux_pool:?}: {e}"
                    ))
                })?;
        }

        // Ensure digest-keyed custom storage volume exists for the guest's
        // network tooling: the DHCP client, and the busybox the init scripts
        // take their interpreter and their programs from.
        let net_tools =
            dhcp_client::load_guest_net_tools(self.config.dhcp_client_bin.as_deref()).await?;
        let dhcp_digest = net_tools.digest;
        let dhcp_volume_name = mapping::dhcp_client_volume_name(&dhcp_digest);
        let dhcp_vol_lock = {
            let mut locks = self.dhcp_client_volume_locks.lock().await;
            locks
                .entry(format!("{aux_pool}/{dhcp_digest}"))
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        {
            let _guard = dhcp_vol_lock.lock().await;
            self.lxd
                .ensure_dhcp_client_volume(
                    aux_pool,
                    &dhcp_volume_name,
                    &net_tools.dhcp_client,
                    &net_tools.busybox,
                    dhcp_client::DHCP_CLIENT_SCRIPT,
                )
                .await
                .map_err(|e| {
                    DriverError::ImageImport(format!(
                        "DHCP client volume provisioning failed on pool {aux_pool:?}: {e}"
                    ))
                })?;
        }

        let devices = mapping::build_create_devices(
            placement,
            &workload_acls,
            gpu.is_some(),
            aux_pool,
            &volume_name,
            aux_pool,
            &dhcp_volume_name,
        );
        let profiles = mapping::build_profiles(template);

        // 1. Create workload instance
        //
        // A create that fails here has already had the sandbox's two ACLs
        // made for it, and LXD has been observed to leave the instance record
        // behind as well (see `create_instance_settling_acl_setup`). Neither
        // has an owner once this returns, so both are cleaned up before the
        // error goes back: otherwise the ACLs wait for the six-hourly
        // collector and the record shows for ever as a sandbox that is
        // provisioning.
        if let Err(e) = self
            .create_instance_settling_acl_setup(
                &sandbox.name,
                &image_alias,
                config,
                devices,
                profiles,
            )
            .await
        {
            self.delete_instance_and_wait(&sandbox.name).await;
            self.delete_sandbox_acl(&sandbox.name).await;
            drop(volume_use);
            return Err(e);
        }

        // Everything from here to the companion's creation runs inside a
        // block whose failure deletes the workload. Without it a create that
        // fails after step 1 — `resolve_workload_identity` refusing a policy
        // account the image does not define is the ordinary case, not an
        // exotic one — leaves an instance carrying the sandbox id, visible
        // for ever as Provisioning, and a retry of the same name gets a 409.
        let staged = async {
            // 2. Resolve the workload's immutable identity and stage the RFC 0012
            //    boundary bootstrap. The identity comes from the pinned image's own
            //    account database, read out of the created-but-stopped instance.
            let identity = self
                .resolve_workload_identity(&sandbox.name, spec, &image_alias)
                .await?;
            let fence = self
                .collect_fence_evidence(
                    &sandbox.name,
                    placement.network,
                    &network.type_.to_string(),
                    &sandbox_acls.protocol,
                )
                .await?;
            let artifacts = isolation::BoundaryArtifacts::new(
                &sandbox.id,
                &launch,
                identity,
                &fence,
                Self::resource_claims(&sandbox.name, self.lxd.project(), &image_alias),
                Self::host_gateway_ip(&Self::resolve_gateway_addresses(&gateway_endpoint).await?),
            )?;
            let workload_guest_files = artifacts.workload_files(&launch, child_env)?;
            Ok::<_, DriverError>((artifacts, workload_guest_files))
        }
        .await;
        let (artifacts, workload_guest_files) = match staged {
            Ok(staged) => staged,
            Err(e) => {
                self.delete_instance_and_wait(&sandbox.name).await;
                self.delete_sandbox_acl(&sandbox.name).await;
                drop(volume_use);
                return Err(e);
            }
        };
        // 3. Configure and create companion supervisor instance
        let sup_name = mapping::supervisor_instance_name(&sandbox.name);
        let mut sup_config = mapping::build_supervisor_config(
            sandbox,
            spec,
            &gateway_endpoint,
            &self.config.log_level,
        );
        // `spec.sandbox_token` is deliberately not staged as a token file any
        // more. It is the sandbox-scoped JWT, and the supervisor would offer
        // whatever OPENSHELL_SANDBOX_TOKEN_FILE points at as its *gateway*
        // credential — which the gateway rejects with "gateway token does not
        // match the active sandbox identity". Under RFC 0012 both tokens come
        // from the launch authentication bundle instead.
        let mut sup_guest_files: Vec<(&str, Vec<u8>)> = Vec::new();
        if self.config.guest_tls().is_some() {
            sup_guest_files.extend(self.read_guest_tls_files().await?);
            mapping::insert_guest_tls_environment(&mut sup_config);
            if let Some(name) = &self.config.gateway_tls_server_name {
                sup_config.insert(
                    "environment.OPENSHELL_GATEWAY_TLS_SERVER_NAME".to_string(),
                    name.clone(),
                );
            }
        }
        // The companion authenticates with the gateway's own bundle, forwarded
        // unchanged. Its backend descriptor is pushed later: it carries the
        // workload's address, which only exists once the workload is running.
        sup_guest_files.push((
            isolation::GUEST_AUTH_BUNDLE_PATH,
            launch.supervisor_bundle()?,
        ));

        let sup_devices = mapping::build_supervisor_devices(
            placement,
            &companion_acls,
            aux_pool,
            &volume_name,
            aux_pool,
            &dhcp_volume_name,
        );
        if let Err(e) = self
            .create_instance_settling_acl_setup(
                &sup_name,
                &supervisor_image_alias,
                sup_config,
                sup_devices,
                vec!["default".to_string()],
            )
            .await
        {
            // Only a companion this create actually made: the name may
            // belong to another sandbox, which is exactly why the create
            // could have failed.
            if let Some(companion) = self.companion_of(&sandbox.name, Some(&sandbox.id)).await {
                self.delete_instance_and_wait(&companion.name).await;
            }
            self.delete_instance_and_wait(&sandbox.name).await;
            self.delete_sandbox_acl(&sandbox.name).await;
            drop(volume_use);
            return Err(e);
        }
        drop(volume_use);

        let post_create = async {
            // Order is forced by the contract, not by preference: the boundary
            // needs its bootstrap before it starts, and the companion needs a
            // descriptor naming the workload's address before it dials. DHCP
            // only assigns that address once the workload is up, so the
            // workload starts first and the companion second.
            self.push_owned_guest_files(&sandbox.name, artifacts.identity(), &workload_guest_files)
                .await?;

            let op = self.lxd.start_instance(&sandbox.name).await?;
            self.wait_operation(&op.id).await?;

            // Settling first: it restarts an init that exits immediately, and
            // the companion must attach to the workload that ends up running,
            // not to the one that just died.
            self.settle_after_start(&sandbox.name, &sandbox.id).await?;

            self.attach_companion(&sandbox.name, &sandbox.id, &artifacts, sup_guest_files)
                .await?;

            Ok::<(), DriverError>(())
        };

        if let Err(post_err) = post_create.await {
            tracing::warn!(
                name = %sandbox.name,
                %post_err,
                "post-create step failed; cleaning up instance"
            );
            let cleanup = async {
                if let Some(companion) = self.companion_of(&sandbox.name, Some(&sandbox.id)).await {
                    if let Ok(op) = self.lxd.stop_instance(&companion.name, true).await {
                        let _ = self.wait_operation(&op.id).await;
                    }
                    self.delete_instance_and_wait(&companion.name).await;
                }
                if let Ok(op) = self.lxd.stop_instance(&sandbox.name, true).await {
                    let _ = self.wait_operation(&op.id).await;
                }
                let op = self.lxd.delete_instance(&sandbox.name).await?;
                self.wait_operation(&op.id).await?;
                self.delete_sandbox_acl(&sandbox.name).await;
                Ok::<(), DriverError>(())
            };
            if let Err(cleanup_err) = cleanup.await {
                tracing::warn!(
                    name = %sandbox.name,
                    %cleanup_err,
                    "failed to clean up instance after post-create failure"
                );
            }
            return Err(post_err);
        }

        Ok(())
    }

    /// Creates an instance, retrying while LXD is still setting the sandbox
    /// network's ACL up in OVN.
    ///
    /// The first instance to attach an ACL makes LXD create that ACL's OVN
    /// port group, and LXD does not serialize it: two sandboxes created at
    /// once both try, and OVN rejects the second with a constraint violation
    /// on the port group's name. It is transient by construction — the group
    /// exists afterwards — and it only became reachable when the egress ACL
    /// stopped being optional, so every create attaches one now.
    ///
    /// Retrying is the driver's to do. A gateway creating two sandboxes at
    /// once is ordinary, and the alternative is a create that fails for a
    /// reason the caller can neither understand nor act on.
    async fn create_instance_settling_acl_setup(
        &self,
        name: &str,
        image_alias: &str,
        config: HashMap<String, String>,
        devices: HashMap<String, HashMap<String, String>>,
        profiles: Vec<String>,
    ) -> Result<(), DriverError> {
        let mut attempt = 0;
        loop {
            let created = self
                .lxd
                .create_instance(
                    name,
                    image_alias,
                    config.clone(),
                    devices.clone(),
                    profiles.clone(),
                    false,
                )
                .await;
            let outcome = match created {
                Ok(op) => self.wait_operation(&op.id).await,
                Err(e) => Err(e.into()),
            };
            let Err(error) = outcome else {
                return Ok(());
            };
            attempt += 1;
            if attempt > ACL_SETUP_RETRIES || !is_acl_setup_race(&error) {
                return Err(error);
            }
            tracing::debug!(
                name = %name,
                attempt,
                %error,
                "LXD raced itself setting the sandbox ACL up in OVN; retrying the create"
            );
            // A create leaves no instance behind when it fails this way, but
            // LXD has been observed to leave the record; remove it so the
            // retry is not refused as a duplicate.
            let _ = self.lxd.delete_instance(name).await;
            tokio::time::sleep(ACL_SETUP_RETRY_DELAY).await;
        }
    }

    async fn instance_lifecycle_lock(&self, name: &str) -> Arc<Mutex<()>> {
        let mut locks = self.lifecycle_locks.lock().await;
        locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Reads the configured sandbox TLS materials, paired with the paths they
    /// go to in the sandbox. Read on every use, so rotated files reach the
    /// next sandbox that is created or started.
    async fn read_guest_tls_files(&self) -> Result<Vec<(&'static str, Vec<u8>)>, DriverError> {
        let Some(tls) = self.config.guest_tls() else {
            return Ok(Vec::new());
        };
        let mut files = Vec::with_capacity(3);
        for (guest_path, host_path) in [
            (mapping::GUEST_TLS_CA_PATH, tls.ca),
            (mapping::GUEST_TLS_CERT_PATH, tls.cert),
            (mapping::GUEST_TLS_KEY_PATH, tls.key),
        ] {
            let content = tokio::fs::read(host_path).await.map_err(|e| {
                DriverError::FailedPrecondition(format!(
                    "could not read the sandbox TLS material {}: {e}",
                    host_path.display()
                ))
            })?;
            files.push((guest_path, content));
        }
        Ok(files)
    }

    /// Pushes files into a stopped sandbox, readable by root only: the
    /// supervisor runs as root, the workload it starts does not.
    async fn push_guest_files(
        &self,
        name: &str,
        files: &[(&str, Vec<u8>)],
    ) -> Result<(), DriverError> {
        for (guest_path, content) in files {
            self.lxd
                .push_file_into_instance(name, guest_path, content)
                .await?;
        }
        Ok(())
    }

    /// Stages protected files into a guest, each with the owner that reads it.
    async fn push_owned_guest_files(
        &self,
        name: &str,
        identity: &isolation::ResolvedWorkloadIdentity,
        files: &[isolation::GuestFile],
    ) -> Result<(), DriverError> {
        // The boundary's own directory must belong to it: it deletes its
        // one-use bootstrap from there once it has been read.
        self.lxd
            .create_dir_in_instance_as(
                name,
                isolation::GUEST_BOUNDARY_DIR,
                identity.uid,
                identity.gid,
                "0700",
            )
            .await?;
        // The boundary installs its proxy CA here and chmods the directory, so
        // it has to own it: /run itself belongs to root.
        self.lxd
            .create_dir_in_instance_as(
                name,
                isolation::GUEST_SUPERVISOR_CA_DIR,
                identity.uid,
                identity.gid,
                "0755",
            )
            .await?;
        for file in files {
            self.lxd
                .push_file_into_instance_as(
                    name,
                    file.path,
                    &file.contents,
                    file.uid,
                    file.gid,
                    file.mode,
                )
                .await?;
        }
        Ok(())
    }

    /// Reads a file out of an instance's rootfs.
    ///
    /// Works on a created-but-stopped instance, which is how the workload's
    /// account database is read before anything in it has run.
    async fn fetch_guest_file(&self, name: &str, path: &str) -> Result<Vec<u8>, DriverError> {
        let (bytes, _mode) = self.lxd.get_file_from_instance(name, path).await?;
        Ok(bytes.to_vec())
    }

    /// Resolves the workload's immutable numeric identity from the pinned
    /// image's own account database, honoring the gateway's selectors.
    async fn resolve_workload_identity(
        &self,
        instance: &str,
        spec: &DriverSandboxSpec,
        resource_digest: &str,
    ) -> Result<isolation::ResolvedWorkloadIdentity, DriverError> {
        let request = spec.workload_identity.as_ref();
        self.resolve_identity_against_image(
            instance,
            request.map_or("", |i| i.user.as_str()),
            request.map_or("", |i| i.group.as_str()),
            resource_digest,
        )
        .await
    }

    /// Re-resolves identity for a restart, where the original request is gone
    /// but the image — and therefore the identity it resolves to — is the same.
    async fn resolve_workload_identity_from_instance(
        &self,
        instance: &str,
        resource_digest: &str,
    ) -> Result<isolation::ResolvedWorkloadIdentity, DriverError> {
        self.resolve_identity_against_image(instance, "", "", resource_digest)
            .await
    }

    async fn resolve_identity_against_image(
        &self,
        instance: &str,
        user: &str,
        group: &str,
        resource_digest: &str,
    ) -> Result<isolation::ResolvedWorkloadIdentity, DriverError> {
        let passwd = self.fetch_guest_file(instance, "/etc/passwd").await?;
        // An image may legitimately ship no /etc/group; a numeric or primary
        // group still resolves without it.
        let group_db = self
            .fetch_guest_file(instance, "/etc/group")
            .await
            .unwrap_or_default();
        isolation::resolve_workload_identity(user, group, &passwd, &group_db, resource_digest)
    }

    /// Immutable LXD coordinates the boundary binds its attachment to.
    ///
    /// The companion sends these in the descriptor and the boundary requires
    /// them to match before it opens its listener, so a descriptor left over
    /// from another instance, project or image cannot be replayed.
    fn resource_claims(
        instance_name: &str,
        project: &str,
        image_alias: &str,
    ) -> std::collections::BTreeMap<String, String> {
        std::collections::BTreeMap::from([
            ("lxd.instance_name".to_string(), instance_name.to_string()),
            ("lxd.project".to_string(), project.to_string()),
            ("lxd.image_alias".to_string(), image_alias.to_string()),
        ])
    }

    /// Reads the outer fence off the instance LXD actually created.
    ///
    /// Every field is an observation, never a restatement of what the create
    /// asked for: whether the ACL is on the NIC, what the NIC's default
    /// actions are, and what else it is attached to. The ACL name the driver
    /// chose says nothing about whether LXD applied it — and on the start
    /// path there was not even a create in this process to restate.
    ///
    /// One read serves all of it, so the extra assurance costs no extra call.
    async fn collect_fence_evidence(
        &self,
        name: &str,
        network: &str,
        network_type: &str,
        fence_acl: &str,
    ) -> Result<isolation::LxdFenceEvidence, DriverError> {
        let instance = self.lxd.get_instance(name).await?;

        // LXD applies a network's own `security.acls` to every NIC on it, and
        // those never show up on the NIC device — so a fence read from the
        // NIC alone cannot see them. Read back here for the same reason as
        // everything else: what LXD has, not what the driver asked for.
        let mut network_acls: Vec<String> = self
            .lxd
            .get_network(network)
            .await
            .ok()
            .and_then(|network| network.config.get("security.acls").cloned())
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|acl| !acl.is_empty())
            .map(str::to_string)
            .collect();
        network_acls.sort();
        network_acls.dedup();

        // Sorted so two devices of the same kind are reported in a stable
        // order: the evidence is hashed into the digest both halves compare.
        let mut devices: Vec<(&String, &HashMap<String, String>)> =
            instance.expanded_devices.iter().collect();
        devices.sort_by_key(|(name, _)| *name);

        // The NIC the fence is installed on, and everything else that could
        // carry a packet off this workload without passing it.
        let mut fenced_nic: Option<&HashMap<String, String>> = None;
        let mut unmediated_egress_paths: Vec<String> = Vec::new();
        for (device_name, device) in devices {
            match device.get("type").map(String::as_str) {
                Some("nic") => {
                    let on_expected_network =
                        device.get("network").map(String::as_str) == Some(network);
                    if on_expected_network && fenced_nic.is_none() {
                        fenced_nic = Some(device);
                        continue;
                    }
                    // Any NIC beyond the fenced one, wherever it points. A
                    // second NIC on the *same* network used to pass unnoticed,
                    // because the check compared network names and this one
                    // matches; so did a `nictype: p2p` NIC, which names
                    // neither a network nor a parent and fell out of the
                    // filter entirely. Neither carries this driver's ACL.
                    let attachment = device
                        .get("network")
                        .or_else(|| device.get("parent"))
                        .map(String::as_str)
                        .unwrap_or("no managed network");
                    unmediated_egress_paths.push(format!("{device_name}: nic on {attachment}"));
                }
                // A proxy device forwards between the host and the container
                // itself, so it is an egress path OVN never sees and no ACL
                // of this driver's can reject.
                Some("proxy") => {
                    unmediated_egress_paths.push(format!("{device_name}: proxy device"));
                }
                // An InfiniBand device is a host adapter handed to the
                // container whole; whatever it carries never reaches OVN.
                Some("infiniband") => {
                    unmediated_egress_paths.push(format!("{device_name}: infiniband device"));
                }
                _ => {}
            }
        }

        let get = |key: &str| -> String {
            fenced_nic
                .and_then(|device| device.get(key))
                .cloned()
                .unwrap_or_default()
        };

        let mut applied_acls: Vec<String> = get("security.acls")
            .split(',')
            .map(str::trim)
            .filter(|acl| !acl.is_empty())
            .map(str::to_string)
            .collect();
        applied_acls.sort();
        applied_acls.dedup();

        Ok(isolation::LxdFenceEvidence {
            instance_name: name.to_string(),
            network: network.to_string(),
            network_type: network_type.to_string(),
            fence_acl: fence_acl.to_string(),
            applied_acls,
            network_acls,
            default_egress_action: get("security.acls.default.egress.action"),
            default_ingress_action: get("security.acls.default.ingress.action"),
            unmediated_egress_paths,
            default_deny_egress_excepts: isolation::LxdFenceEvidence::DEFAULT_DENY_EGRESS_EXCEPTS,
        })
    }

    /// Starts the supervisor companion against a running workload.
    ///
    /// A workload that is not running has no boundary to supervise: its
    /// condition already says why, and attaching a companion would only
    /// replace that reason with a less useful one. Leaving the companion
    /// stopped is also what lets the sandbox be started again later.
    async fn attach_companion(
        &self,
        name: &str,
        sandbox_id: &str,
        artifacts: &isolation::BoundaryArtifacts,
        mut files: Vec<(&str, Vec<u8>)>,
    ) -> Result<(), DriverError> {
        let Some(workload_ip) = self.wait_for_instance_ipv4(name).await? else {
            return Ok(());
        };
        files.push(artifacts.descriptor_file(name, workload_ip)?);

        // The wait above runs unlocked and lasts up to a minute. A stop that
        // arrives inside it takes the free lifecycle lock, stops both halves
        // and returns — and an attach that then went ahead on what it saw
        // before would start the companion of a sandbox that is meant to be
        // down. That pair, a running companion over a stopped workload, is
        // one no later call can repair: start refuses a companion that is not
        // stopped, and stop returns early on a workload that already is. So
        // everything the attach depends on is re-read here, under the lock it
        // will hold until the companion is up.
        let lifecycle_lock = self.instance_lifecycle_lock(name).await;
        let _guard = lifecycle_lock.lock().await;

        let instance = self.lxd.get_instance(name).await?;
        if instance
            .config
            .get(mapping::KEY_SANDBOX_ID)
            .map(String::as_str)
            != Some(sandbox_id)
        {
            // Deleted and recreated under the same name while we waited.
            return Ok(());
        }
        if !instance.status.eq_ignore_ascii_case("Running")
            || instance.config.contains_key(mapping::KEY_STOP_INTENT)
        {
            return Ok(());
        }
        let Some(companion) = self.companion_of(name, Some(sandbox_id)).await else {
            return Ok(());
        };

        self.push_guest_files(&companion.name, &files).await?;
        // Cleared here, immediately before the start, so the window above
        // reports a companion that is stopped on purpose rather than one that
        // died.
        self.clear_stop_intent(&companion.name).await;
        let op = self.lxd.start_instance(&companion.name).await?;
        self.wait_operation(&op.id).await?;
        Ok(())
    }

    /// Waits for the workload to acquire the IPv4 address the companion dials.
    ///
    /// The address is assigned by DHCP from inside the container, so it
    /// appears some time after start rather than at start.
    ///
    /// Returns `None` when the workload is no longer running. A sandbox whose
    /// init exits immediately never gets an address, and that is a state the
    /// gateway needs reported — as `ContainerExited`, with the console log to
    /// explain it — rather than one to stall on and then tear down.
    async fn wait_for_instance_ipv4(
        &self,
        name: &str,
    ) -> Result<Option<std::net::Ipv4Addr>, DriverError> {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(BOUNDARY_ADDRESS_TIMEOUT_SECS);
        loop {
            match self.lxd.get_instance_state(name).await {
                Ok(state) => {
                    let found = state
                        .network
                        .iter()
                        .filter(|(iface, _)| iface.as_str() != "lo")
                        .flat_map(|(_, net)| net.addresses.iter())
                        .filter(|a| a.family == "inet")
                        .find_map(|a| a.address.parse::<std::net::Ipv4Addr>().ok());
                    if let Some(ip) = found {
                        return Ok(Some(ip));
                    }
                    if !state.status.eq_ignore_ascii_case("Running")
                        && !state.status.eq_ignore_ascii_case("Starting")
                    {
                        tracing::warn!(
                            name = %name,
                            status = %state.status,
                            "workload stopped before it acquired an address; not attaching \
                             a supervisor companion to it"
                        );
                        return Ok(None);
                    }
                }
                Err(e) => tracing::debug!(name = %name, %e, "instance state unavailable"),
            }
            if std::time::Instant::now() >= deadline {
                return Err(DriverError::Internal(format!(
                    "workload instance {name:?} did not acquire an IPv4 address within \
                     {BOUNDARY_ADDRESS_TIMEOUT_SECS}s; the supervisor companion cannot reach \
                     its sandbox boundary without one"
                )));
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// Starts a stopped sandbox again, idempotently.
    ///
    /// The instance keeps its token and configuration across a stop; the TLS
    /// materials are pushed again so a restarted sandbox gets the current
    /// ones. The stop marker is cleared before starting, so a sandbox that
    /// later exits by itself is reported as `ContainerExited` rather than as
    /// stopped on request, but restored if the start fails.
    pub async fn start_sandbox(
        &self,
        name: &str,
        launch_authentication: &[u8],
    ) -> Result<(), DriverError> {
        let lifecycle_lock = self.instance_lifecycle_lock(name).await;
        let (sandbox_id, artifacts, launch) = {
            let _guard = lifecycle_lock.lock().await;

            let instance = self.get_managed_instance(name).await?;
            // The policy may have changed since this sandbox was created, and
            // what it was created with outlives the flag that allowed it.
            self.check_config_provenance(&instance)?;
            // Settling re-reads the instance; the id tells a restart of this
            // sandbox from one that reused the name in the meantime.
            let sandbox_id = instance
                .config
                .get(mapping::KEY_SANDBOX_ID)
                .cloned()
                .unwrap_or_default();
            let mut had_stop_intent = instance.config.contains_key(mapping::KEY_STOP_INTENT);
            match instance.status.as_str() {
                "Stopped" => {}
                // Already up, or on its way there — unless the companion
                // never attached. The attach runs after the workload is up
                // and can be lost to a failed file push, a DHCP wait that
                // times out, or the driver being cancelled or restarted mid
                // way; what it leaves behind is a running workload beside a
                // companion that is stopped with its deliberate-stop marker
                // still on it. That pair reads as "starting", which is true
                // of the create window and false for ever afterwards, and a
                // start that returned OK here would leave the gateway waiting
                // on a sandbox that has nothing left to finish it.
                //
                // RFC 0012 gives every start-from-stopped a fresh session, so
                // the half-started generation cannot be resumed: it is
                // stopped here and started again below, which is what a
                // caller asking for a start wants anyway.
                "Running" | "Ready" | "Starting" => {
                    let companion = self.companion_of(name, Some(&sandbox_id)).await;
                    let attached = companion
                        .as_ref()
                        .is_some_and(|companion| !companion.status.eq_ignore_ascii_case("Stopped"));
                    if attached || instance.status == "Starting" {
                        return Ok(());
                    }
                    tracing::warn!(
                        sandbox = %name,
                        "workload is running with its companion stopped; the attach did not \
                         finish, so the sandbox is being started again from stopped"
                    );
                    self.set_stop_intent(name).await;
                    had_stop_intent = true;
                    self.stop_instance_with_deadline(name).await?;
                }
                // Anything else — paused, stopping, broken — would not be running
                // after an "OK" here.
                other => {
                    return Err(DriverError::FailedPrecondition(format!(
                        "sandbox instance is {other}, not stopped; it can be started once it has stopped"
                    )));
                }
            }

            // By ownership, not by name: another sandbox may hold the
            // name this sandbox's companion would have, and pushing TLS
            // material into it — let alone starting it — would be acting on
            // someone else's sandbox.
            let sup = self
                .companion_of(name, Some(&sandbox_id))
                .await
                .ok_or_else(|| {
                    DriverError::FailedPrecondition(format!(
                        "sandbox {name:?} has no supervisor companion; it cannot be started \
                     without the trusted half, so delete it and create it again"
                    ))
                })?;

            // Not best-effort: these are the gateway's current client
            // credentials, and a companion that starts with the previous
            // rotation's cannot reach the gateway at all. Failing the start
            // says so, where swallowing it produced a sandbox that came up
            // and then could not be talked to.
            let tls_files = self.read_guest_tls_files().await?;
            if !tls_files.is_empty() {
                self.push_guest_files(&sup.name, &tls_files).await?;
            }

            // The companion's marker stays until `attach_companion` actually
            // starts it. Clearing it here would leave it, for the whole of
            // the settle and the DHCP wait, as a companion that is stopped
            // with no record of being stopped on purpose — which reads as
            // "stopped unexpectedly", a reason the gateway treats as
            // terminal, for a sandbox that is merely starting.

            if !sup.status.eq_ignore_ascii_case("Stopped") {
                return Err(DriverError::FailedPrecondition(format!(
                    "companion supervisor instance is {}, not stopped; it can be started once it has stopped",
                    sup.status
                )));
            }

            // RFC 0012 gives every start-from-stopped a fresh session, so the
            // previous generation's descriptor, bootstrap and TLS identity are
            // all stale: the boundary rejects them. Stage new ones.
            //
            // The credentials are required here. The gateway omits them only
            // when it already considers the sandbox Ready, which the status
            // check above has already returned on.
            let launch = isolation::LaunchAuthentication::decode(launch_authentication)?;
            let image_alias = instance
                .config
                .get(mapping::KEY_IMAGE_ALIAS)
                .cloned()
                .unwrap_or_default();
            let network = instance
                .config
                .get(mapping::KEY_NETWORK)
                .cloned()
                .unwrap_or_default();
            let identity = self
                .resolve_workload_identity_from_instance(name, &image_alias)
                .await?;
            // A sandbox that comes back after the gateway moved has to
            // reach the new address, and its own ACL is the only place that
            // is written down. Re-ensured before the fence is read, so the
            // evidence describes the ACL this start installed.
            let mut host_gateway_ip = None;
            if let Ok(lxd_network) = self.lxd.get_network(&network).await {
                match self.resolve_gateway_endpoint(&network, &lxd_network) {
                    Ok(endpoint) => {
                        self.ensure_sandbox_acls(name, &endpoint).await?;
                        host_gateway_ip = Self::host_gateway_ip(
                            &Self::resolve_gateway_addresses(&endpoint).await?,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(sandbox = %name, %e, "could not refresh the sandbox ACL");
                    }
                }
            }

            // The recorded keys say what this sandbox was created with;
            // the evidence says what its NIC carries now. A fence taken away
            // between a stop and a start has to fail the start, not be
            // attested from the record of the create that installed it.
            let fence = self
                .collect_fence_evidence(
                    name,
                    &network,
                    instance
                        .config
                        .get(mapping::KEY_NETWORK_TYPE)
                        .map(String::as_str)
                        .unwrap_or_default(),
                    instance
                        .config
                        .get(mapping::KEY_EGRESS_ACL)
                        .map(String::as_str)
                        .unwrap_or_default(),
                )
                .await?;
            let artifacts = isolation::BoundaryArtifacts::new(
                &sandbox_id,
                &launch,
                identity,
                &fence,
                Self::resource_claims(name, self.lxd.project(), &image_alias),
                host_gateway_ip,
            )?;
            // The declared environment was recorded at create; the instance's
            // own environment.* keys also carry plumbing the workload must
            // not see.
            let child_env: HashMap<String, String> = instance
                .config
                .get(mapping::KEY_CHILD_ENV)
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_default();
            self.push_owned_guest_files(
                name,
                artifacts.identity(),
                &artifacts.workload_files(&launch, child_env)?,
            )
            .await?;

            // Cleared here and nowhere earlier. Everything above can fail,
            // and a sandbox that was stopped on request must still read as
            // stopped on request if it does — not as one whose init exited,
            // which the gateway treats as terminal rather than recoverable.
            if had_stop_intent {
                self.clear_stop_intent(name).await;
            }

            // Workload first: the companion's descriptor names the address
            // DHCP only assigns once the workload is up.
            let op = match self.lxd.start_instance(name).await {
                Ok(op) => op,
                Err(e) => {
                    if had_stop_intent {
                        self.set_stop_intent(name).await;
                    }
                    return Err(e.into());
                }
            };
            if let Err(e) = self.wait_operation(&op.id).await {
                if had_stop_intent {
                    if let Ok(current) = self.lxd.get_instance(name).await {
                        if current.status.eq_ignore_ascii_case("Stopped") {
                            self.set_stop_intent(name).await;
                        }
                    }
                }
                return Err(e);
            }

            (sandbox_id, artifacts, launch)
        };

        // Outside the lifecycle lock, and after settling: settling restarts an
        // init that exits immediately, and the companion must attach to the
        // workload that ends up running.
        self.settle_after_start(name, &sandbox_id).await?;
        self.attach_companion(
            name,
            &sandbox_id,
            &artifacts,
            vec![(
                isolation::GUEST_AUTH_BUNDLE_PATH,
                launch.supervisor_bundle()?,
            )],
        )
        .await
    }

    /// Records that the driver stopped this sandbox deliberately (see
    /// [`mapping::KEY_STOP_INTENT`]).
    ///
    /// Best-effort: the marker only refines the reason reported for a stopped
    /// sandbox, so failing to write it must not fail the stop itself.
    /// [`Self::start_sandbox`] clears it.
    async fn set_stop_intent(&self, name: &str) {
        let mut config = HashMap::new();
        config.insert(
            mapping::KEY_STOP_INTENT.to_string(),
            Some(mapping::CONDITION_STOPPED.to_string()),
        );
        if let Err(e) = self.lxd.patch_instance_config(name, config).await {
            tracing::debug!(name = %name, %e, "could not record stop intent");
        }
    }

    async fn clear_stop_intent(&self, name: &str) {
        let mut config = HashMap::new();
        config.insert(mapping::KEY_STOP_INTENT.to_string(), None);
        if let Err(e) = self.lxd.patch_instance_config(name, config).await {
            tracing::debug!(name = %name, %e, "could not clear stop intent");
        }
    }

    /// Restarts a sandbox whose init exited immediately after the first start.
    ///
    /// The container's init is the supervisor, so if it gives up during
    /// start-up — for example because its first policy sync lost a race with
    /// the gateway finishing the sandbox record — PID 1 exits, LXD reports
    /// the instance `Stopped`, and nothing brings it back: LXD's
    /// `boot.autorestart` is VM-only, and `boot.autostart` only covers daemon
    /// restarts. A bounded retry turns that transient into a working sandbox
    /// instead of one wedged in `Error`.
    async fn settle_after_start(
        &self,
        name: &str,
        expected_sandbox_id: &str,
    ) -> Result<(), DriverError> {
        let lifecycle_lock = self.instance_lifecycle_lock(name).await;
        for attempt in 0..self.config.start_retries {
            // Give init long enough to fail; a supervisor that is going to
            // exit on a start-up race does so within a few seconds.
            tokio::time::sleep(SETTLE_DELAY).await;

            let _guard = lifecycle_lock.lock().await;

            let instance = match self.lxd.get_instance(name).await {
                Ok(i) => i,
                Err(LxdError::Api {
                    status_code: 404, ..
                }) => return Ok(()),
                Err(e) => return Err(e.into()),
            };
            if instance
                .config
                .get(mapping::KEY_SANDBOX_ID)
                .map(String::as_str)
                != Some(expected_sandbox_id)
            {
                return Ok(());
            }
            if !instance.status.eq_ignore_ascii_case("Stopped") {
                return Ok(());
            }
            // Stopped because it was asked to be, while this start settled:
            // restarting it would undo that stop.
            if instance.config.contains_key(mapping::KEY_STOP_INTENT) {
                return Ok(());
            }

            tracing::warn!(
                name = %name,
                attempt = attempt + 1,
                "sandbox init exited immediately after start; restarting"
            );
            let op = self.lxd.start_instance(name).await?;
            self.wait_operation(&op.id).await?;
        }
        Ok(())
    }

    /// Confirms that the network and storage pool a sandbox is placed on
    /// exist, before anything slow (an image import) or anything that would
    /// need cleaning up (volumes, the instance) happens. Returns the network.
    ///
    /// A missing one is a `FailedPrecondition` naming it and how to choose
    /// another, which the gateway passes on to the user as is; LXD's own 404
    /// ("Network not found") names neither.
    async fn check_placement(
        &self,
        placement: mapping::Placement<'_>,
    ) -> Result<lxd_client::Network, DriverError> {
        let project = &self.config.project;
        let network = match self.lxd.get_network(placement.network).await {
            Ok(network) => network,
            Err(LxdError::Api {
                status_code: 404, ..
            }) => {
                return Err(DriverError::FailedPrecondition(format!(
                    "LXD network {:?} does not exist in project {project:?}; point the sandbox's \
                     driver_config.network, the driver's --default-network, or the NIC device of \
                     the project's default profile at an existing one",
                    placement.network
                )));
            }
            Err(e) => return Err(e.into()),
        };
        if !self.lxd.storage_pool_exists(placement.storage_pool).await? {
            return Err(DriverError::FailedPrecondition(format!(
                "LXD storage pool {:?} does not exist; point the sandbox's \
                 driver_config.storage_pool, the driver's --default-storage-pool, or the root \
                 disk device of the project's default profile at an existing one",
                placement.storage_pool
            )));
        }
        Ok(network)
    }

    /// Ensures the ACL every sandbox on `network_name` shares, and returns
    /// its name (see [`crate::egress`]).
    ///
    /// Its rules are a constant, so after the first sandbox on a network this
    /// finds it already right and writes nothing.
    async fn ensure_network_egress_acl(
        &self,
        network_name: &str,
        network: &lxd_client::Network,
    ) -> Result<String, DriverError> {
        if network.type_ != NetworkType::Ovn {
            return Err(DriverError::FailedPrecondition(format!(
                "sandboxes need an OVN network, where LXD applies ACLs to each NIC: the \
                 egress ACL is the outer network fence OpenShell v0.1.0 requires before a \
                 workload runs, and LXD rejects a per-NIC ACL anywhere else. {network_name:?} \
                 is a {} network",
                network.type_
            )));
        }

        let name = crate::egress::acl_name(network_name);
        self.lxd
            .ensure_network_acl(&name, crate::egress::network_rules(), Vec::new())
            .await?;
        Ok(name)
    }

    /// The two ACLs one sandbox owns.
    ///
    /// `protocol` is carried by both halves and is the whole of what the
    /// workload is allowed; `egress` is carried by the companion alone.
    /// Ensures this sandbox's own ACLs — the protocol ACL both halves carry,
    /// and the egress ACL only the companion carries.
    ///
    /// Written on create and again on start, so a sandbox that comes back
    /// after the gateway moved reaches the new address. Nothing else rewrites
    /// it: it belongs to one sandbox, so one sandbox's lifecycle is the only
    /// thing that touches it.
    async fn ensure_sandbox_acls(
        &self,
        sandbox_name: &str,
        gateway_endpoint: &str,
    ) -> Result<SandboxAcls, DriverError> {
        let gateway = Self::resolve_gateway_addresses(gateway_endpoint).await?;

        // The protocol ACL first: the companion's egress rules name it as
        // their subject, and LXD validates a subject against the ACLs that
        // exist when the rule is written.
        let protocol = crate::egress::sandbox_protocol_acl_name(sandbox_name);
        let (egress, ingress) = crate::egress::sandbox_protocol_rules(&protocol);
        self.lxd
            .ensure_network_acl(&protocol, egress, ingress)
            .await?;

        let fence_acl = crate::egress::sandbox_egress_acl_name(sandbox_name);
        self.lxd
            .ensure_network_acl(
                &fence_acl,
                crate::egress::companion_egress_rules(&gateway, &protocol),
                Vec::new(),
            )
            .await?;

        Ok(SandboxAcls {
            protocol,
            egress: fence_acl,
        })
    }

    /// Resolves the gateway endpoint to the addresses a sandbox dials.
    ///
    /// Used both for the ACL that permits them and for the descriptor's
    /// `host_gateway_ip`, so the address the fence allows and the address the
    /// supervisor's network mediation trusts cannot disagree.
    async fn resolve_gateway_addresses(
        gateway_endpoint: &str,
    ) -> Result<Vec<std::net::SocketAddr>, DriverError> {
        let url = url::Url::parse(gateway_endpoint).map_err(|e| {
            DriverError::FailedPrecondition(format!(
                "gateway endpoint {gateway_endpoint:?} is not a URL: {e}"
            ))
        })?;
        let port = url.port_or_known_default().unwrap_or(443);
        let addresses: Vec<std::net::SocketAddr> = match url.host() {
            Some(url::Host::Ipv4(ip)) => vec![(ip, port).into()],
            Some(url::Host::Ipv6(ip)) => vec![(ip, port).into()],
            Some(url::Host::Domain(host)) => tokio::net::lookup_host((host, port))
                .await
                .map_err(|e| {
                    DriverError::FailedPrecondition(format!(
                        "cannot resolve gateway endpoint host {host:?} for the egress ACL: {e}"
                    ))
                })?
                .collect(),
            None => Vec::new(),
        };
        if addresses.is_empty() {
            return Err(DriverError::FailedPrecondition(format!(
                "gateway endpoint {gateway_endpoint:?} names no address for the egress ACL"
            )));
        }
        Ok(addresses)
    }

    /// The trusted dial target for the reserved host-gateway aliases.
    ///
    /// Policy DNS refuses `host.openshell.internal` and its siblings on the
    /// mediated path without one (`TrustedGatewayUnavailable`), because the
    /// supervisor's network mediation will not resolve a reserved alias
    /// through the workload's own resolver view. The driver is the only
    /// component that knows the address, which is why upstream's Docker
    /// driver derives it from its endpoint, Kubernetes takes it as operator
    /// configuration and the VM driver hard-codes its loopback.
    ///
    /// IPv4 first: a sandbox's NIC gets its address by DHCP over IPv4, so
    /// that is the family it can actually dial.
    fn host_gateway_ip(gateway: &[std::net::SocketAddr]) -> Option<std::net::IpAddr> {
        gateway
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| gateway.first())
            .map(std::net::SocketAddr::ip)
    }

    /// Removes a sandbox's own ACL once both its instances are gone.
    ///
    /// Best-effort: LXD refuses to delete an ACL still in use, and clean-up
    /// collects one left behind. Leaving it is harmless — it grants nothing
    /// to a NIC that no longer exists — but it is this sandbox's, so it goes
    /// with it.
    async fn delete_sandbox_acl(&self, sandbox_name: &str) {
        for name in [
            crate::egress::sandbox_egress_acl_name(sandbox_name),
            crate::egress::sandbox_protocol_acl_name(sandbox_name),
        ] {
            if let Err(e) = self.lxd.delete_network_acl(&name).await {
                tracing::debug!(sandbox = %sandbox_name, acl = %name, %e, "could not delete the sandbox ACL");
            }
        }
    }

    /// Resolves `OPENSHELL_ENDPOINT`: `--gateway-endpoint` when set, otherwise
    /// the host-side address of the sandbox's network and the configured
    /// gateway gRPC port.
    fn resolve_gateway_endpoint(
        &self,
        network_name: &str,
        network: &lxd_client::Network,
    ) -> Result<String, DriverError> {
        if let Some(endpoint) = &self.config.gateway_endpoint {
            return Ok(endpoint.clone());
        }
        // An OVN network's address is its virtual router's, which nothing on
        // the host can listen on; deriving the endpoint from it would send
        // every supervisor to the router.
        if network.type_ == NetworkType::Ovn {
            return Err(DriverError::FailedPrecondition(format!(
                "network {network_name:?} is an OVN network, whose address belongs to its \
                 virtual router rather than the gateway; set the driver's --gateway-endpoint \
                 to the URL sandboxes reach the gateway at"
            )));
        }
        let cidr = network.config.get("ipv4.address").ok_or_else(|| {
            DriverError::FailedPrecondition(format!(
                "network {network_name:?} has no ipv4.address configured"
            ))
        })?;
        let host_ip = cidr.split('/').next().unwrap_or(cidr);
        let port = self.config.gateway_grpc_port;
        Ok(format!(
            "{}://{host_ip}:{port}",
            self.config.gateway_scheme()
        ))
    }

    pub async fn stop_sandbox(&self, name: &str) -> Result<(), DriverError> {
        let lifecycle_lock = self.instance_lifecycle_lock(name).await;
        let _guard = lifecycle_lock.lock().await;

        let instance = self.get_managed_instance(name).await?;
        let sandbox_id = instance
            .config
            .get(mapping::KEY_SANDBOX_ID)
            .cloned()
            .unwrap_or_default();

        // Marked and swept before the workload's own state is consulted, and
        // both unconditionally. A stopped workload is not the end of the
        // story: its companion outlives it whenever the workload went down
        // without it — an init that exited, a forced stop whose wait timed
        // out, an attach that raced a stop — and returning here left that
        // companion running with no call able to stop it. The marker is
        // idempotent, and writing it on a workload that is already stopped is
        // what lets a retried stop repair one that stopped without it and
        // would otherwise read as having exited on its own.
        self.set_stop_intent(name).await;

        // Stop companion supervisor container before workload container
        // (INV-4), and only one that is actually this sandbox's generation.
        if let Some(companion) = self.companion_of(name, Some(&sandbox_id)).await {
            self.set_stop_intent(&companion.name).await;
            let _ = self.stop_instance_with_deadline(&companion.name).await;
        }

        if instance.status.eq_ignore_ascii_case("Stopped") {
            return Ok(());
        }

        // Stop workload container
        self.stop_instance_with_deadline(name).await
    }

    async fn stop_instance_with_deadline(&self, name: &str) -> Result<(), DriverError> {
        let graceful = async {
            let op = self
                .lxd
                .stop_instance_timeout(name, false, self.config.stop_timeout_secs)
                .await?;
            self.wait_operation(&op.id).await
        };

        match graceful.await {
            Ok(()) => return Ok(()),
            Err(DriverError::Lxd(ref e)) if is_already_stopped(e) => return Ok(()),
            Err(e) => {
                tracing::debug!(
                    name = %name,
                    %e,
                    "graceful stop did not complete; forcing"
                );
            }
        }

        let op = match self.lxd.stop_instance(name, true).await {
            Ok(op) => op,
            Err(e) if is_already_stopped(&e) => return Ok(()),
            Err(e) => {
                self.clear_stop_intent(name).await;
                return Err(e.into());
            }
        };
        if let Err(e) = self.wait_operation(&op.id).await {
            if !matches!(&e, DriverError::Lxd(lxd_err) if is_already_stopped(lxd_err)) {
                self.clear_stop_intent(name).await;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Deletes a sandbox by instance name, idempotently.
    ///
    /// Returns `Some(sandbox_id)` (the `user.openshell.sandbox_id` from the
    /// instance config, used by the gRPC layer to broadcast a WatchSandboxes
    /// Deleted event) if the sandbox was deleted, or `None` if it was not
    /// found — the caller may retry safely.
    pub async fn delete_sandbox(&self, name: &str) -> Result<Option<String>, DriverError> {
        let lifecycle_lock = self.instance_lifecycle_lock(name).await;
        let _guard = lifecycle_lock.lock().await;

        let instance = match self.lxd.get_instance(name).await {
            Ok(i) => i,
            Err(LxdError::Api {
                status_code: 404, ..
            }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(sandbox_id) = instance.config.get(mapping::KEY_SANDBOX_ID).cloned() else {
            // Not driver-managed: treat as not found rather than deleting an
            // arbitrary LXD instance the caller happened to name correctly.
            return Ok(None);
        };
        // A companion carries the sandbox id too, so the id alone does not say
        // this is a sandbox. Naming a companion directly would otherwise
        // delete another sandbox's trusted half and report *its* id as the
        // deleted sandbox. Every other entry point filters this through
        // `get_managed_instance`; this one has to do it itself, because it
        // must still answer for an instance that is not fully managed.
        if instance.config.get(mapping::KEY_ROLE).map(String::as_str)
            == Some(mapping::ROLE_SUPERVISOR)
        {
            return Ok(None);
        }

        // Stop and delete companion supervisor instance first (INV-3).
        // Resolved by ownership, not by name: an instance that merely holds
        // this sandbox's companion name may be another sandbox's workload,
        // and deleting that would destroy it.
        //
        // Both errors are fatal to the delete. Going on to remove the
        // workload would leave the companion running with the gateway bundle
        // it was staged with, and out of reach: the retry the gateway makes
        // looks the sandbox up by the workload's name, gets a 404 and reports
        // the sandbox deleted, so nothing ever comes back for it. Its NIC
        // keeps the sandbox's ACLs in use and its disks keep the aux volumes
        // pinned, so the collector cannot reclaim them either. Failing here
        // instead leaves both halves in place for a retry that can still find
        // them.
        if let Some(companion) = self.companion_of(name, Some(&sandbox_id)).await {
            match self.lxd.stop_instance(&companion.name, true).await {
                Ok(op) => {
                    if let Err(e) = self.wait_operation(&op.id).await {
                        if !matches!(&e, DriverError::Lxd(lxd_err) if is_already_stopped(lxd_err)) {
                            return Err(e);
                        }
                    }
                }
                Err(e) if is_already_stopped(&e) => {}
                Err(LxdError::Api {
                    status_code: 404, ..
                }) => {}
                Err(e) => return Err(e.into()),
            }
            match self.lxd.delete_instance(&companion.name).await {
                Ok(op) => self.wait_operation(&op.id).await?,
                Err(LxdError::Api {
                    status_code: 404, ..
                }) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // Force-stop before deleting; LXD rejects deletion of running instances.
        match self.lxd.stop_instance(name, true).await {
            Ok(op) => {
                if let Err(e) = self.wait_operation(&op.id).await {
                    if !matches!(&e, DriverError::Lxd(lxd_err) if is_already_stopped(lxd_err)) {
                        return Err(e);
                    }
                }
            }
            Err(e) if is_already_stopped(&e) => {}
            Err(LxdError::Api {
                status_code: 404, ..
            }) => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let op = match self.lxd.delete_instance(name).await {
            Err(LxdError::Api {
                status_code: 404, ..
            }) => return Ok(None),
            other => other?,
        };
        self.wait_operation(&op.id).await?;
        // Both instances are gone, so nothing carries this sandbox's ACL any
        // more and LXD will let it go.
        self.delete_sandbox_acl(name).await;
        {
            let mut locks = self.lifecycle_locks.lock().await;
            if Arc::strong_count(&lifecycle_lock) <= 2 {
                locks.remove(name);
            }
        }
        Ok(Some(sandbox_id))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use clap::Parser;
    use computev1::pb::{
        DriverSandboxSpec, DriverSandboxTemplate, GpuResourceRequirements, ResourceRequirements,
    };
    use lxd_client::LxdEndpoint;

    use super::*;
    use crate::config::DEFAULT_LXD_SOCKET;

    fn driver() -> LxdComputeDriver {
        let config = Config::parse_from(["openshell-driver-lxd"]);
        let lxd =
            LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();
        LxdComputeDriver::new(config, lxd)
    }

    fn sandbox_with_spec(spec: DriverSandboxSpec) -> DriverSandbox {
        DriverSandbox {
            id: "id".to_string(),
            name: "name".to_string(),
            namespace: "default".to_string(),
            workspace: "default".to_string(),
            spec: Some(spec),
            status: None,
        }
    }

    fn spec_with_labels(labels: HashMap<String, String>) -> DriverSandboxSpec {
        DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                labels,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn spec_with_gpu_count(count: Option<u32>) -> DriverSandboxSpec {
        DriverSandboxSpec {
            template: Some(DriverSandboxTemplate::default()),
            resource_requirements: Some(ResourceRequirements {
                gpu: Some(GpuResourceRequirements { count }),
            }),
            ..Default::default()
        }
    }

    /// The text is all LXD gives for this one: the REST API reports it as a
    /// generic operation failure carrying `ovn-nbctl`'s output. Recorded
    /// verbatim from LXD 6.9, so a change in wording fails here rather than
    /// silently turning the retry off.
    #[test]
    fn lxds_own_acl_setup_race_is_recognized() {
        let observed = DriverError::Lxd(lxd_client::LxdError::OperationFailed {
            description: "Creating instance".to_string(),
            err: "Creating instance: Failed creating instance record: Failed initialising \
                  instance: Failed adding device \"eth0\": Failed adding OVN port: Failed \
                  ensuring security ACLs are configured in OVN for instance: Failed creating \
                  port group \"lxd_acl0\" for referenced security ACL \"127.0.0.1\" setup: \
                  Failed running: ovn-nbctl ... transaction error: {\"details\":\"Transaction \
                  causes multiple rows in \\\"Port_Group\\\" table to have identical values \
                  (lxd_acl0) for index on column \\\"name\\\".\",\"error\":\"constraint \
                  violation\"}"
                .to_string(),
        });
        assert!(is_acl_setup_race(&observed));

        // The same contention, at the other point LXD sets a NIC's ACLs up —
        // where `ovn-nbctl` was seen to abort rather than refuse.
        let aborted = DriverError::Lxd(lxd_client::LxdError::OperationFailed {
            description: "Creating instance".to_string(),
            err: "Creating instance: Failed creating instance record: Failed initialising \
                  instance: Failed adding device \"eth0\": Failed adding OVN port: Failed \
                  applying OVN default ACL rules for instance NIC: Failed applying instance \
                  NIC default ACL rules for port \"lxd-net2-instance-...-eth0\": Failed \
                  running: ovn-nbctl ... : signal: aborted (core dumped)"
                .to_string(),
        });
        assert!(is_acl_setup_race(&aborted));

        // The same race, reported the other way LXD 6.9 was seen to report it.
        let also_observed = DriverError::Lxd(lxd_client::LxdError::OperationFailed {
            description: "Creating instance".to_string(),
            err: "Creating instance: Failed creating instance record: Failed initialising \
                  instance: Failed adding device \"eth0\": Failed adding OVN port: Failed \
                  ensuring security ACLs are configured in OVN for instance: Failed creating \
                  port group \"lxd_acl0\" for referenced security ACL \"127.0.0.1\" setup: \
                  Failed running: ovn-nbctl ... exit status 1 (ovn-nbctl: multiple rows in \
                  Port_Group match \"lxd_acl0\")"
                .to_string(),
        });
        assert!(is_acl_setup_race(&also_observed));

        // Anything else is a real failure and must not be retried.
        for other in [
            DriverError::Lxd(lxd_client::LxdError::OperationFailed {
                description: "Creating instance".to_string(),
                err: "Failed creating instance record: Failed getting root disk: No root disk \
                      device found"
                    .to_string(),
            }),
            DriverError::InvalidArgument("nope".to_string()),
        ] {
            assert!(!is_acl_setup_race(&other), "{other:?}");
        }
    }

    #[test]
    fn capabilities_reports_static_fields() {
        let response = driver().capabilities();

        assert_eq!(response.driver_name, "lxd");
        assert_eq!(response.driver_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(response.default_image, "nvcr.io/nvidia/base/ubuntu:24.04");
        assert!(!response.driver_reports_runtime_readiness);
        let resources = response
            .resource_capabilities
            .expect("resource capabilities are reported");
        assert!(resources.cpu.expect("cpu").limit_supported);
        assert!(resources.memory.expect("memory").limit_supported);
        let gpu = resources.gpu.expect("gpu");
        assert!(gpu.default_selection_supported);
        // A count needs host GPU inventory the driver does not collect.
        assert!(!gpu.count_selection_supported);
        // The driver pulls images; it takes no rootfs tar from the gateway.
        assert_eq!(response.rootfs_tar_staging_dir, "");
        assert_eq!(response.rootfs_tar_max_bytes, 0);
    }

    #[tokio::test]
    async fn validate_sandbox_create_rejects_invalid_label_key() {
        let mut labels = HashMap::new();
        labels.insert("bad key".to_string(), "value".to_string());
        let sandbox = sandbox_with_spec(spec_with_labels(labels));

        let err = driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("invalid label key should be rejected");

        assert!(matches!(err, DriverError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_valid_label_key() {
        let mut labels = HashMap::new();
        labels.insert("team.example-key_1".to_string(), "value".to_string());
        let sandbox = sandbox_with_spec(spec_with_labels(labels));

        driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect("valid label key should be accepted");
    }

    #[tokio::test]
    async fn validate_sandbox_create_rejects_zero_gpu_count() {
        let sandbox = sandbox_with_spec(spec_with_gpu_count(Some(0)));

        let err = driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("gpu.count == 0 should be rejected");

        assert!(matches!(err, DriverError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_omitted_gpu_count() {
        let sandbox = sandbox_with_spec(spec_with_gpu_count(None));

        driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect("omitted gpu.count should be accepted");
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_explicit_gpu_count() {
        let sandbox = sandbox_with_spec(spec_with_gpu_count(Some(1)));

        driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect("gpu.count >= 1 should be accepted");
    }

    fn spec_with_driver_config(fields: &[(&str, &str)]) -> DriverSandboxSpec {
        let fields = fields
            .iter()
            .map(|(key, value)| {
                (
                    (*key).to_string(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue((*value).to_string())),
                    },
                )
            })
            .collect();
        DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                driver_config: Some(prost_types::Struct { fields }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The gateway's default policy forbids caller driver config, and the
    /// driver acknowledges that policy, so it has to refuse one too — a
    /// gateway is not the only thing that can reach the driver's socket.
    #[tokio::test]
    async fn validate_sandbox_create_rejects_caller_driver_config_by_default() {
        let sandbox = sandbox_with_spec(spec_with_driver_config(&[("storage_pool", "remote")]));

        let error = driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("caller driver config should be refused by default");
        assert!(
            matches!(error, DriverError::FailedPrecondition(_)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_caller_driver_config_when_allowed() {
        let config = Config::parse_from(["openshell-driver-lxd", "--allow-driver-config"]);
        let lxd =
            LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();
        let sandbox = sandbox_with_spec(spec_with_driver_config(&[("storage_pool", "remote")]));

        LxdComputeDriver::new(config, lxd)
            .validate_sandbox_create(&sandbox)
            .await
            .expect("caller driver config should be accepted when allowed");
    }

    /// The flag can be turned off after a sandbox exists, and what it was
    /// created with outlives the flag that allowed it. Checking the flag
    /// alone at start would answer a different question.
    #[test]
    fn a_start_re_checks_what_the_sandbox_was_created_with() {
        let permissive = {
            let config = Config::parse_from(["openshell-driver-lxd", "--allow-driver-config"]);
            let lxd =
                LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();
            LxdComputeDriver::new(config, lxd)
        };
        let strict = driver();

        let recorded = |value: Option<&str>| {
            let mut instance = lxd_client::Instance {
                name: "sb".to_string(),
                description: String::new(),
                status: "Stopped".to_string(),
                status_code: 0,
                architecture: String::new(),
                ephemeral: false,
                profiles: Vec::new(),
                config: HashMap::new(),
                devices: HashMap::new(),
                expanded_devices: HashMap::new(),
                type_: "container".to_string(),
                project: "default".to_string(),
            };
            if let Some(value) = value {
                instance.config.insert(
                    mapping::KEY_CALLER_DRIVER_CONFIG.to_string(),
                    value.to_string(),
                );
            }
            instance
        };

        // Created without caller config: admissible either way.
        strict
            .check_config_provenance(&recorded(Some("false")))
            .expect("a sandbox created with no caller config is always admissible");
        permissive
            .check_config_provenance(&recorded(Some("false")))
            .expect("a sandbox created with no caller config is always admissible");

        // Created with it: only while the policy still allows it.
        permissive
            .check_config_provenance(&recorded(Some("true")))
            .expect("still allowed");
        assert!(
            strict
                .check_config_provenance(&recorded(Some("true")))
                .is_err(),
            "a sandbox created with caller config must not start once it is disabled"
        );

        // No record at all: fails closed, as upstream's does.
        assert!(strict.check_config_provenance(&recorded(None)).is_err());
        assert!(permissive.check_config_provenance(&recorded(None)).is_err());
    }

    /// An empty block is what a gateway forwards for a sandbox that named no
    /// driver config at all; refusing it would refuse every sandbox.
    #[tokio::test]
    async fn validate_sandbox_create_accepts_an_empty_driver_config() {
        let sandbox = sandbox_with_spec(spec_with_driver_config(&[]));

        driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect("an empty driver config is not caller configuration");
    }

    /// Allowing caller driver config changes what the gateway must be
    /// configured with, so it has to change the acknowledgement too.
    #[test]
    fn allowing_driver_config_changes_the_acknowledged_policy() {
        let config = Config::parse_from(["openshell-driver-lxd", "--allow-driver-config"]);
        let lxd =
            LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();
        let permissive = LxdComputeDriver::new(config, lxd).capabilities();

        assert_ne!(
            permissive.resource_admission_policy,
            driver().capabilities().resource_admission_policy
        );
    }

    /// An LXD container is user-namespaced unless it is made privileged, so
    /// the only answer this driver can give to `false` is "no".
    #[tokio::test]
    async fn validate_sandbox_create_refuses_a_sandbox_outside_a_user_namespace() {
        let mut spec = spec_with_labels(HashMap::new());
        spec.template.as_mut().unwrap().user_namespaces = Some(false);

        let error = driver()
            .validate_sandbox_create(&sandbox_with_spec(spec))
            .await
            .expect_err("a privileged container is not on offer");
        assert!(
            matches!(error, DriverError::InvalidArgument(_)),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_the_user_namespace_it_already_provides() {
        for requested in [None, Some(true)] {
            let mut spec = spec_with_labels(HashMap::new());
            spec.template.as_mut().unwrap().user_namespaces = requested;

            driver()
                .validate_sandbox_create(&sandbox_with_spec(spec))
                .await
                .unwrap_or_else(|e| {
                    panic!("user_namespaces = {requested:?} should be accepted: {e}")
                });
        }
    }

    #[tokio::test]
    async fn validate_sandbox_create_requires_identity_spec_and_template() {
        let complete = || sandbox_with_spec(spec_with_labels(HashMap::new()));
        let cases = [
            (
                "sandbox.name",
                DriverSandbox {
                    name: String::new(),
                    ..complete()
                },
            ),
            (
                "sandbox.id",
                DriverSandbox {
                    id: String::new(),
                    ..complete()
                },
            ),
            (
                "sandbox.spec",
                DriverSandbox {
                    spec: None,
                    ..complete()
                },
            ),
            (
                "sandbox.spec.template",
                sandbox_with_spec(DriverSandboxSpec::default()),
            ),
        ];

        for (field, sandbox) in cases {
            let err = driver()
                .validate_sandbox_create(&sandbox)
                .await
                .expect_err("incomplete sandbox should be rejected");
            match err {
                DriverError::InvalidArgument(msg) => {
                    assert!(msg.contains(field), "expected {field} in {msg:?}");
                }
                other => panic!("expected InvalidArgument for missing {field}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn validate_sandbox_create_rejects_empty_label_key() {
        let mut labels = HashMap::new();
        labels.insert(String::new(), "value".to_string());
        let sandbox = sandbox_with_spec(spec_with_labels(labels));

        let err = driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("empty label key should be rejected");
        assert!(matches!(err, DriverError::InvalidArgument(_)));
    }

    /// A malformed reference can never be imported, so it is refused as the
    /// caller's mistake before CreateSandbox runs.
    #[tokio::test]
    async fn validate_sandbox_create_rejects_malformed_image_reference() {
        let sandbox = sandbox_with_spec(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                image: "UPPER/Case::bad".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });

        let err = driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect_err("malformed image reference should be rejected");
        assert!(matches!(err, DriverError::InvalidArgument(_)), "{err:?}");
    }

    #[tokio::test]
    async fn validate_sandbox_create_accepts_a_well_formed_image_reference() {
        let sandbox = sandbox_with_spec(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                image: "nvcr.io/nvidia/base/ubuntu:24.04".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });

        driver()
            .validate_sandbox_create(&sandbox)
            .await
            .expect("a well-formed reference should be accepted without contacting a registry");
    }

    #[test]
    fn capabilities_report_configured_default_image() {
        let config = Config::parse_from([
            "openshell-driver-lxd",
            "--default-image",
            "registry.example.com/sandboxes/custom:v2",
        ]);
        let lxd =
            LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();

        let response = LxdComputeDriver::new(config, lxd).capabilities();

        assert_eq!(
            response.default_image,
            "registry.example.com/sandboxes/custom:v2"
        );
    }

    /// Messages as LXD 6.9 reports them: synchronously (400) when the
    /// instance is already stopped at request time, or on the operation when
    /// it stopped while the request was in flight.
    #[test]
    fn already_stopped_is_recognized_from_sync_and_async_errors() {
        let sync_already_stopped = LxdError::Api {
            status_code: 400,
            message: "The instance is already stopped".to_string(),
        };
        assert!(is_already_stopped(&sync_already_stopped));

        let async_already_stopped = LxdError::OperationFailed {
            description: "Stopping instance".to_string(),
            err: "The instance is already stopped".to_string(),
        };
        assert!(is_already_stopped(&async_already_stopped));

        let async_not_running = LxdError::OperationFailed {
            description: "Stopping instance".to_string(),
            err: "Instance is not running".to_string(),
        };
        assert!(is_already_stopped(&async_not_running));
    }

    /// Anything else must propagate: swallowing it would report a stop that
    /// did not happen.
    #[test]
    fn other_errors_are_not_mistaken_for_already_stopped() {
        let cases = [
            LxdError::Api {
                status_code: 400,
                message: "Invalid config".to_string(),
            },
            // Only a 400 carries the synchronous "already stopped" meaning.
            LxdError::Api {
                status_code: 500,
                message: "The instance is already stopped".to_string(),
            },
            LxdError::Api {
                status_code: 404,
                message: "Instance not found".to_string(),
            },
            LxdError::OperationFailed {
                description: "Stopping instance".to_string(),
                err: "Failed shutting down instance, status is \"Running\": context deadline exceeded"
                    .to_string(),
            },
            LxdError::Io(std::io::Error::other("already stopped")),
        ];

        for err in cases {
            assert!(!is_already_stopped(&err), "{err:?}");
        }
    }

    struct MockAliasChecker {
        exists: bool,
    }

    #[tonic::async_trait]
    impl crate::image::ImageAliasChecker for MockAliasChecker {
        async fn image_alias_exists(&self, _alias: &str) -> Result<bool, DriverError> {
            Ok(self.exists)
        }
    }

    struct MockImporter {
        digest: String,
        imported_alias: std::sync::Mutex<Option<String>>,
    }

    #[tonic::async_trait]
    impl crate::image::OciImporter for MockImporter {
        async fn resolve_digest(&self, _reference: &str) -> Result<String, DriverError> {
            Ok(self.digest.clone())
        }

        async fn import(
            &self,
            _reference: &str,
            _digest: &str,
            alias: &str,
        ) -> Result<(), DriverError> {
            *self.imported_alias.lock().unwrap() = Some(alias.to_string());
            Ok(())
        }

        async fn extract_supervisor_binary(
            &self,
            _reference: &str,
            cache_dir: &std::path::Path,
        ) -> Result<(std::path::PathBuf, String), DriverError> {
            let target_dir = cache_dir.join("test-digest");
            let binary_path = target_dir.join("openshell-sandbox");
            if !binary_path.exists() {
                std::fs::create_dir_all(&target_dir).unwrap();
                std::fs::write(&binary_path, b"mock-supervisor").unwrap();
            }
            Ok((binary_path, self.digest.clone()))
        }
    }

    #[tokio::test]
    async fn create_sandbox_resolves_image_or_defaults() {
        let config = Config::parse_from(["openshell-driver-lxd"]);
        let lxd =
            LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap();

        let digest_hex = "ee".repeat(32);
        let importer = Arc::new(MockImporter {
            digest: format!("sha256:{digest_hex}"),
            imported_alias: std::sync::Mutex::new(None),
        });
        let checker = Arc::new(MockAliasChecker { exists: true });
        let cache =
            ImageCache::with_checker(checker, importer, config.image_cache_alias_prefix.clone());

        let driver = LxdComputeDriver::with_image_cache(config, lxd, cache);

        // 1. Empty template.image falls back to default_image, which is now
        //    itself an OCI reference resolved through the same import path.
        let empty_spec = DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                image: "".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let _sb_empty = sandbox_with_spec(empty_spec);
        assert_eq!(
            driver.config.default_image,
            "nvcr.io/nvidia/base/ubuntu:24.04"
        );

        // 2. Non-empty template.image resolves to the digest-derived alias
        let custom_spec = DriverSandboxSpec {
            template: Some(DriverSandboxTemplate {
                image: "registry.example.com/custom:v1".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let sb_custom = sandbox_with_spec(custom_spec);
        let template = sb_custom.spec.unwrap().template.unwrap();
        let resolved = driver
            .image_cache
            .resolve_alias(&template.image)
            .await
            .unwrap();
        assert_eq!(
            resolved,
            format!("openshell-oci-r{}-{digest_hex}", image::CONVERSION_REVISION)
        );
    }
}
