// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core LXD compute driver logic, independent of the gRPC transport.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use computev1::pb::{DriverSandbox, GetCapabilitiesResponse};
use lxd_client::{LxdClient, LxdError};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::dhcp_client;
use crate::error::DriverError;
use crate::image::{self, digest_of_file, ImageCache, SkopeoImporter};
use crate::mapping;

const DRIVER_NAME: &str = "lxd";

/// How long to let a freshly started sandbox settle before checking that its
/// init is still up. See [`LxdComputeDriver::settle_after_start`].
const SETTLE_DELAY: Duration = Duration::from_secs(3);

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
        }
    }

    /// Best-effort pre-warm of the default sandbox image so the first
    /// `create_sandbox` need not block on a registry pull, and so a bad
    /// default reference or an unreachable registry surfaces at startup
    /// rather than on the first request. Importing requires the external
    /// tooling (skopeo/umoci/mksquashfs); any failure here is logged and
    /// otherwise ignored — the same import is retried on first use.
    pub async fn ensure_default_image(&self) -> Result<String, DriverError> {
        self.image_cache
            .resolve_alias(&self.config.default_image)
            .await
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
            driver_version: env!("CARGO_PKG_VERSION").to_string(),
            default_image: self.config.default_image.clone(),
            // The gateway would stop sandboxes when it shuts down and restart
            // them with StartSandbox when it comes back, which this driver
            // does not implement. Sandboxes keep running across gateway
            // restarts instead.
            gateway_manages_lifecycle: false,
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
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| DriverError::InvalidArgument("sandbox.spec is required".into()))?;
        let template = spec.template.as_ref().ok_or_else(|| {
            DriverError::InvalidArgument("sandbox.spec.template is required".into())
        })?;

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

        Ok(())
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
        if !instance.config.contains_key(mapping::KEY_SANDBOX_ID) {
            return Err(not_found());
        }
        Ok(instance)
    }

    pub async fn get_sandbox(&self, name: &str) -> Result<DriverSandbox, DriverError> {
        let instance = self.get_managed_instance(name).await?;
        Ok(mapping::instance_to_driver_sandbox(&instance))
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, DriverError> {
        let instances = self.lxd.list_instances().await?;
        Ok(instances
            .iter()
            .filter(|i| i.config.contains_key(mapping::KEY_SANDBOX_ID))
            .map(mapping::instance_to_driver_sandbox)
            .collect())
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
            .find(|i| i.config.get(mapping::KEY_SANDBOX_ID).map(String::as_str) == Some(sandbox_id))
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

        let placement = mapping::Placement::resolve(
            template,
            &self.config.default_network,
            &self.config.default_storage_pool,
        );
        let network = self.check_placement(placement).await?;

        let has_token = !spec.sandbox_token.is_empty();
        let gateway_endpoint = self.resolve_gateway_endpoint(placement.network, &network)?;
        let config = mapping::build_create_config(
            sandbox,
            spec,
            template,
            &gateway_endpoint,
            has_token,
            self.config.default_max_processes,
        )?;

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
        // Resolve supervisor binary and digest
        let (binary_path, digest) = match &self.config.supervisor_bin {
            Some(path) => (path.clone(), digest_of_file(path)?),
            None => self
                .image_cache
                .extract_supervisor_binary(
                    &self.config.supervisor_image,
                    &self.config.supervisor_cache_dir,
                )
                .await
                .map_err(|e| {
                    DriverError::ImageImport(format!("supervisor binary extraction failed: {e}"))
                })?,
        };

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

        // Ensure digest-keyed custom storage volume exists for the DHCP client
        let (dhcp_binary_bytes, dhcp_digest) =
            dhcp_client::load_dhcp_client(self.config.dhcp_client_bin.as_deref()).await?;
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
                    &dhcp_binary_bytes,
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
            gpu.is_some(),
            aux_pool,
            &volume_name,
            aux_pool,
            &dhcp_volume_name,
        );
        let profiles = mapping::build_profiles(template);

        let image_alias = if template.image.is_empty() {
            self.image_cache
                .resolve_alias(&self.config.default_image)
                .await?
        } else {
            self.image_cache.resolve_alias(&template.image).await?
        };

        // Create the instance stopped so we can push the token file before the
        // supervisor starts — avoids a race where the supervisor reads
        // OPENSHELL_SANDBOX_TOKEN_FILE before it has been written.
        let op = self
            .lxd
            .create_instance(
                &sandbox.name,
                &image_alias,
                config,
                devices,
                profiles,
                false,
            )
            .await?;
        self.wait_operation(&op.id).await?;

        let post_create = async {
            if has_token {
                self.lxd
                    .push_file_into_instance(
                        &sandbox.name,
                        mapping::GUEST_SANDBOX_TOKEN_PATH,
                        spec.sandbox_token.as_bytes(),
                    )
                    .await?;
            }

            let op = self.lxd.start_instance(&sandbox.name).await?;
            self.wait_operation(&op.id).await?;
            self.settle_after_start(&sandbox.name, &sandbox.id).await?;

            Ok::<(), DriverError>(())
        };

        if let Err(post_err) = post_create.await {
            tracing::warn!(
                name = %sandbox.name,
                %post_err,
                "post-create step failed; cleaning up instance"
            );
            let cleanup = async {
                if let Ok(op) = self.lxd.stop_instance(&sandbox.name, true).await {
                    let _ = self.wait_operation(&op.id).await;
                }
                let op = self.lxd.delete_instance(&sandbox.name).await?;
                self.wait_operation(&op.id).await
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

    async fn instance_lifecycle_lock(&self, name: &str) -> Arc<Mutex<()>> {
        let mut locks = self.lifecycle_locks.lock().await;
        locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Records that the driver stopped this sandbox deliberately (see
    /// [`mapping::KEY_STOP_INTENT`]).
    ///
    /// Best-effort: the marker only refines the reason reported for a stopped
    /// sandbox, so failing to write it must not fail the stop itself. Nothing
    /// clears it because this driver exposes no start RPC — a stopped sandbox
    /// is only ever deleted. A future `StartSandbox` would need to clear it so
    /// a later crash is not reported as a deliberate stop.
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
                    "LXD network {:?} does not exist in project {project:?}; set the sandbox's \
                     driver_config.network or the driver's --default-network to an existing one",
                    placement.network
                )));
            }
            Err(e) => return Err(e.into()),
        };
        if !self.lxd.storage_pool_exists(placement.storage_pool).await? {
            return Err(DriverError::FailedPrecondition(format!(
                "LXD storage pool {:?} does not exist; set the sandbox's \
                 driver_config.storage_pool or the driver's --default-storage-pool to an existing one",
                placement.storage_pool
            )));
        }
        Ok(network)
    }

    /// Resolves `OPENSHELL_ENDPOINT` from the sandbox's own target network's
    /// host-side bridge IP and the configured gateway gRPC port.
    fn resolve_gateway_endpoint(
        &self,
        network_name: &str,
        network: &lxd_client::Network,
    ) -> Result<String, DriverError> {
        let cidr = network.config.get("ipv4.address").ok_or_else(|| {
            DriverError::FailedPrecondition(format!(
                "network {network_name:?} has no ipv4.address configured"
            ))
        })?;
        let host_ip = cidr.split('/').next().unwrap_or(cidr);
        let port = self.config.gateway_grpc_port;
        Ok(format!("http://{host_ip}:{port}"))
    }

    pub async fn stop_sandbox(&self, name: &str) -> Result<(), DriverError> {
        let lifecycle_lock = self.instance_lifecycle_lock(name).await;
        let _guard = lifecycle_lock.lock().await;

        let instance = self.get_managed_instance(name).await?;
        if instance.status.eq_ignore_ascii_case("Stopped") {
            return Ok(());
        }

        // Record that this stop was asked for, before issuing it. LXD reports
        // the same `Stopped` status however an instance went down, so without
        // this marker a requested stop is indistinguishable from the init
        // dying and would be reported as `ContainerExited` — surfacing to the
        // user as `Error` instead of `Stopped`.
        self.set_stop_intent(name).await;

        // Ask politely first, but with a deadline. The sandbox's init is the
        // supervisor, which does not act on LXD's shutdown signal, so an
        // unbounded graceful stop never completes: the LXD operation stays
        // RUNNING, the instance stays up, and StopSandbox only fails once the
        // driver's own operation timeout fires. Bounding it here means the
        // graceful attempt fails fast and the forced stop below is what
        // actually stops the sandbox.
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

    #[test]
    fn capabilities_reports_static_fields() {
        let response = driver().capabilities();

        assert_eq!(response.driver_name, "lxd");
        assert_eq!(response.driver_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            response.default_image,
            "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
        );
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
                image: "ghcr.io/nvidia/openshell-community/sandboxes/base:latest".to_string(),
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
            "ghcr.io/nvidia/openshell-community/sandboxes/base:latest"
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
        assert_eq!(resolved, format!("openshell-oci-r3-{digest_hex}"));
    }
}
