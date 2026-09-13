// SPDX-License-Identifier: AGPL-3.0-or-later

//! Translation between the proto's `DriverSandbox`/`DriverSandboxTemplate`
//! shapes and LXD's instance config/devices/profiles shapes.

use std::collections::HashMap;

use computev1::pb::{
    DriverCondition, DriverSandbox, DriverSandboxSpec, DriverSandboxStatus, DriverSandboxTemplate,
};
use lxd_client::{resources, Instance};
use prost_types::value::Kind;
use prost_types::Struct;

use crate::error::DriverError;

pub(crate) const KEY_SANDBOX_ID: &str = "user.openshell.sandbox_id";
const KEY_NAMESPACE: &str = "user.openshell.namespace";
const KEY_WORKSPACE: &str = "user.openshell.workspace";
const LABEL_PREFIX: &str = "user.openshell.label.";
const ENV_PREFIX: &str = "environment.";

/// Identifies the guest-side path where the token file is bind-mounted.
/// The supervisor finds it via `OPENSHELL_SANDBOX_TOKEN_FILE`.
pub(crate) const GUEST_SANDBOX_TOKEN_PATH: &str = "/etc/openshell/auth/sandbox.jwt";

/// Identifies the guest-side Unix socket path where the supervisor binds its
/// SSH relay listener. The supervisor reads it via `OPENSHELL_SSH_SOCKET_PATH`.
pub(crate) const GUEST_SSH_SOCKET_PATH: &str = "/run/openshell/ssh.sock";

/// Environment variable carrying the sandbox's canonical main process to the
/// supervisor (OpenShell v0.0.116 `openshell-core::sandbox_env::MAIN_PROCESS_SPEC`).
pub(crate) const ENV_MAIN_PROCESS_SPEC: &str = "OPENSHELL_MAIN_PROCESS_SPEC";

/// Version of the [`ENV_MAIN_PROCESS_SPEC`] encoding the supervisor accepts.
const MAIN_PROCESS_SPEC_VERSION: u32 = 1;

/// Encodes the sandbox's main process for [`ENV_MAIN_PROCESS_SPEC`]:
/// `{"version":1,"command":[...],"tty":bool}`, the JSON form upstream's
/// `MainProcessConfig` decodes.
///
/// An empty command means the supervisor's default interactive shell — the
/// same fallback upstream applies — because the supervisor rejects a spec
/// whose command is empty.
pub fn main_process_spec(spec: &DriverSandboxSpec) -> String {
    let (command, tty) = if spec.command.is_empty() {
        (vec!["/bin/bash".to_string(), "-l".to_string()], true)
    } else {
        (spec.command.clone(), spec.tty)
    };
    serde_json::json!({
        "version": MAIN_PROCESS_SPEC_VERSION,
        "command": command,
        "tty": tty,
    })
    .to_string()
}

/// Guest-side directory where the digest-keyed supervisor storage volume is mounted.
pub(crate) const GUEST_SUPERVISOR_BIN_DIR: &str = "/opt/openshell/bin";

/// Guest-side directory where the digest-keyed DHCP client storage volume is mounted.
pub(crate) const GUEST_DHCP_CLIENT_DIR: &str = "/opt/openshell/net";

/// Guest-side executable path of the supervisor binary inside the mounted volume directory.
#[allow(dead_code)]
pub(crate) const GUEST_SUPERVISOR_BIN_PATH: &str = "/opt/openshell/bin/openshell-sandbox";

/// Deterministic LXD custom storage volume name for the given supervisor binary digest.
pub(crate) fn supervisor_volume_name(digest: &str) -> String {
    let clean = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("openshell-supervisor-{clean}")
}

/// Deterministic LXD custom storage volume name for the given DHCP client digest.
pub(crate) fn dhcp_client_volume_name(digest: &str) -> String {
    let clean = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("openshell-dhcp-client-{clean}")
}

/// Maps an [`Instance`] to a [`DriverSandbox`] observation. `spec` is left
/// unset, per the proto's own doc comment: "Drivers may omit this in observed
/// snapshots returned by Get/List/Watch."
pub fn instance_to_driver_sandbox(instance: &Instance) -> DriverSandbox {
    DriverSandbox {
        id: instance
            .config
            .get(KEY_SANDBOX_ID)
            .cloned()
            .unwrap_or_default(),
        name: instance.name.clone(),
        namespace: instance
            .config
            .get(KEY_NAMESPACE)
            .cloned()
            .unwrap_or_default(),
        workspace: instance
            .config
            .get(KEY_WORKSPACE)
            .cloned()
            .unwrap_or_default(),
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: instance.name.clone(),
            instance_id: instance.name.clone(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![ready_condition(instance)],
            deleting: false,
        }),
    }
}

/// Ready-condition reason when a sandbox's init exited on its own — an
/// ordinary application exit or a crash.
///
/// Terminal: the gateway deliberately does not relaunch these at startup, so a
/// genuine failure keeps its error signal.
pub(crate) const CONDITION_EXITED: &str = "ContainerExited";

/// Ready-condition reason when a sandbox was stopped through the API, i.e. the
/// driver was asked to stop it. The gateway treats this as recoverable.
pub(crate) const CONDITION_STOPPED: &str = "ContainerStopped";

/// Ready-condition reason while a sandbox exists but has not been started yet.
/// In the gateway's transient set, so it maps to `Provisioning`, not `Error`.
pub(crate) const CONDITION_CREATED: &str = "ContainerCreated";

/// Ready-condition reason while a sandbox is starting. Also transient.
pub(crate) const CONDITION_STARTING: &str = "ContainerStarting";

/// Ready-condition reason when a sandbox is frozen/paused.
pub(crate) const CONDITION_PAUSED: &str = "ContainerPaused";

/// Instance config key recording that the *driver* stopped this sandbox.
///
/// LXD reports a plain `Stopped` status whichever way an instance went down —
/// `volatile.last_state.power` is `STOPPED` both when the init exited by itself
/// and when the API stopped it — so intent has to be recorded when the stop is
/// issued. Without it a user-requested stop would be reported as
/// [`CONDITION_EXITED`] and surface as `Error` instead of `Stopped`.
pub(crate) const KEY_STOP_INTENT: &str = "user.openshell.stop_intent";

/// LXD sets this volatile key the first time an instance starts, so its absence
/// distinguishes "created, never started" from "ran and is now down".
const KEY_LAST_POWER: &str = "volatile.last_state.power";

/// Maps an instance's observed state to the `Ready` condition.
///
/// The reason strings mirror the cross-driver vocabulary in upstream's
/// `openshell-core::driver_utils` (`ContainerExited`, `ContainerStopped`) and
/// the Podman and Docker drivers (`ContainerStarting`, `ContainerCreated`,
/// `ContainerPaused`). This driver is out-of-tree and cannot import those,
/// but the gateway keys real behaviour off these exact strings — which of
/// them are transient (→ `Provisioning` rather than `Error`) and which are
/// eligible for recovery at gateway startup — so they must match upstream
/// verbatim.
///
/// The message is what the gateway shows the user next to the reason, so a
/// sandbox that is not ready always says why, and where to look.
fn ready_condition(instance: &Instance) -> DriverCondition {
    let (status, reason, message) = match instance.status.as_str() {
        // A guest that signalled readiness over devlxd reports `Ready`; treat
        // it as running rather than falling through to `Unknown`.
        "Running" | "Ready" => ("True", "", String::new()),
        "Stopped" => {
            if !instance.config.contains_key(KEY_LAST_POWER) {
                // Created but never started: still provisioning, not a failure.
                (
                    "False",
                    CONDITION_CREATED,
                    "sandbox instance is created but has not started yet".to_string(),
                )
            } else if instance.config.contains_key(KEY_STOP_INTENT) {
                (
                    "False",
                    CONDITION_STOPPED,
                    "sandbox instance was stopped on request".to_string(),
                )
            } else {
                (
                    "False",
                    CONDITION_EXITED,
                    format!(
                        "sandbox supervisor exited and the instance stopped; its output is in \
                         `lxc console {} --show-log`",
                        lxc_target(instance)
                    ),
                )
            }
        }
        "Starting" => (
            "False",
            CONDITION_STARTING,
            "sandbox instance is starting".to_string(),
        ),
        "Frozen" => (
            "False",
            CONDITION_PAUSED,
            "sandbox instance is frozen".to_string(),
        ),
        "Error" => (
            "False",
            "Error",
            format!(
                "LXD reports the sandbox instance in an error state; see `lxc info {} --show-log`",
                lxc_target(instance)
            ),
        ),
        // "Unknown" status (not "False") → gateway maps to Provisioning, not Error.
        other => (
            "Unknown",
            "Unknown",
            format!("LXD reports unrecognized instance status {other:?}"),
        ),
    };
    DriverCondition {
        r#type: "Ready".to_string(),
        status: status.to_string(),
        reason: reason.to_string(),
        message,
        last_transition_time: String::new(),
    }
}

/// How to name `instance` on an `lxc` command line: its name, plus
/// `--project` outside the default project.
fn lxc_target(instance: &Instance) -> String {
    if instance.project.is_empty() || instance.project == lxd_client::DEFAULT_PROJECT {
        instance.name.clone()
    } else {
        format!("{} --project {}", instance.name, instance.project)
    }
}

/// Builds the LXD instance `config` map for `POST /1.0/instances`.
///
/// Sets `OPENSHELL_SANDBOX_ID`, `OPENSHELL_SANDBOX`,
/// `OPENSHELL_SSH_SOCKET_PATH` (pointing to [`GUEST_SSH_SOCKET_PATH`]) and
/// [`ENV_MAIN_PROCESS_SPEC`] unconditionally.
///
/// `gateway_endpoint` is the resolved `OPENSHELL_ENDPOINT` value
/// (`http://<host-ip>:<gateway-grpc-port>`). When empty the env var is not
/// set — the gateway is expected to supply it via `spec.environment` instead.
///
/// `has_token` indicates whether a sandbox JWT token will be pushed into the
/// container (via `POST /1.0/instances/<name>/files`). When `true`, the
/// `OPENSHELL_SANDBOX_TOKEN_FILE` env var is injected so the supervisor reads
/// the file the driver pushes at `GUEST_SANDBOX_TOKEN_PATH` before start.
pub fn build_create_config(
    sandbox: &DriverSandbox,
    spec: &DriverSandboxSpec,
    template: &DriverSandboxTemplate,
    gateway_endpoint: &str,
    has_token: bool,
    default_max_processes: u32,
) -> Result<HashMap<String, String>, DriverError> {
    let mut config = HashMap::new();

    config.insert(KEY_SANDBOX_ID.to_string(), sandbox.id.clone());
    config.insert(KEY_NAMESPACE.to_string(), sandbox.namespace.clone());
    config.insert(KEY_WORKSPACE.to_string(), sandbox.workspace.clone());
    // The supervisor installs its own seccomp BPF filter around the agent
    // process and uses clone/unshare for namespace setup. security.nesting
    // enables those paths.
    config.insert("security.nesting".to_string(), "true".to_string());

    // template.environment takes precedence over spec.environment on key
    // collision, plus the two driver-injected vars the supervisor needs to
    // reach the gateway.
    for (key, value) in &spec.environment {
        config.insert(format!("{ENV_PREFIX}{key}"), value.clone());
    }
    for (key, value) in &template.environment {
        config.insert(format!("{ENV_PREFIX}{key}"), value.clone());
    }
    config.insert(
        format!("{ENV_PREFIX}OPENSHELL_SANDBOX_ID"),
        sandbox.id.clone(),
    );
    config.insert(
        format!("{ENV_PREFIX}OPENSHELL_SANDBOX"),
        sandbox.name.clone(),
    );
    config.insert(
        format!("{ENV_PREFIX}OPENSHELL_SSH_SOCKET_PATH"),
        GUEST_SSH_SOCKET_PATH.to_string(),
    );
    // Without this the supervisor runs its default shell instead of the
    // command the sandbox was created with.
    config.insert(
        format!("{ENV_PREFIX}{ENV_MAIN_PROCESS_SPEC}"),
        main_process_spec(spec),
    );
    if !gateway_endpoint.is_empty() {
        config.insert(
            format!("{ENV_PREFIX}OPENSHELL_ENDPOINT"),
            gateway_endpoint.to_string(),
        );
    }
    if has_token {
        config.insert(
            format!("{ENV_PREFIX}OPENSHELL_SANDBOX_TOKEN_FILE"),
            GUEST_SANDBOX_TOKEN_PATH.to_string(),
        );
    }

    for (key, value) in &template.labels {
        if !is_valid_label_key(key) {
            return Err(DriverError::InvalidArgument(format!(
                "invalid label key {key:?}: must match [a-zA-Z0-9._-]+"
            )));
        }
        config.insert(format!("{LABEL_PREFIX}{key}"), value.clone());
    }

    if let Some(resources) = &template.resources {
        let cpu = if !resources.cpu_limit.is_empty() {
            &resources.cpu_limit
        } else {
            &resources.cpu_request
        };
        if !cpu.is_empty() {
            config.insert("limits.cpu".to_string(), resources::cpu_limit_to_lxd(cpu)?);
        }

        let memory = if !resources.memory_limit.is_empty() {
            &resources.memory_limit
        } else {
            &resources.memory_request
        };
        if !memory.is_empty() {
            config.insert(
                "limits.memory".to_string(),
                resources::memory_limit_to_lxd(memory)?,
            );
        }
    }

    // Bound the sandbox's PID count. Sandboxes run untrusted agent workloads
    // on a shared host, so an unlimited `pids.max` lets one sandbox fork-bomb
    // its co-tenants; the supervisor warns about this on every boot when it
    // finds the cgroup unlimited.
    let max_processes = max_processes(template).unwrap_or(default_max_processes);
    if max_processes > 0 {
        config.insert("limits.processes".to_string(), max_processes.to_string());
    }

    Ok(config)
}

/// Per-sandbox `limits.processes` override from `driver_config.max_processes`.
fn max_processes(template: &DriverSandboxTemplate) -> Option<u32> {
    let value = template
        .driver_config
        .as_ref()?
        .fields
        .get("max_processes")?
        .kind
        .as_ref()?;
    match value {
        Kind::NumberValue(n)
            if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 && *n <= u32::MAX as f64 =>
        {
            Some(*n as u32)
        }
        Kind::StringValue(s) => s.parse::<u32>().ok(),
        _ => None,
    }
}

/// Builds the LXD `devices` map for `POST /1.0/instances`: a root disk on
/// the placement's storage pool, a NIC on its network, a read-only supervisor
/// disk volume, a read-only DHCP client disk volume, and an optional GPU
/// device.
pub fn build_create_devices(
    placement: Placement<'_>,
    gpu: bool,
    supervisor_pool: &str,
    supervisor_volume: &str,
    dhcp_client_pool: &str,
    dhcp_client_volume: &str,
) -> HashMap<String, HashMap<String, String>> {
    let mut devices = HashMap::new();

    let mut root = HashMap::new();
    root.insert("type".to_string(), "disk".to_string());
    root.insert("pool".to_string(), placement.storage_pool.to_string());
    root.insert("path".to_string(), "/".to_string());
    devices.insert("root".to_string(), root);

    let mut eth0 = HashMap::new();
    eth0.insert("type".to_string(), "nic".to_string());
    eth0.insert("network".to_string(), placement.network.to_string());
    devices.insert("eth0".to_string(), eth0);

    let mut supervisor = HashMap::new();
    supervisor.insert("type".to_string(), "disk".to_string());
    supervisor.insert("pool".to_string(), supervisor_pool.to_string());
    supervisor.insert("source".to_string(), supervisor_volume.to_string());
    supervisor.insert("path".to_string(), GUEST_SUPERVISOR_BIN_DIR.to_string());
    supervisor.insert("readonly".to_string(), "true".to_string());
    devices.insert("supervisor".to_string(), supervisor);

    let mut dhcp_client = HashMap::new();
    dhcp_client.insert("type".to_string(), "disk".to_string());
    dhcp_client.insert("pool".to_string(), dhcp_client_pool.to_string());
    dhcp_client.insert("source".to_string(), dhcp_client_volume.to_string());
    dhcp_client.insert("path".to_string(), GUEST_DHCP_CLIENT_DIR.to_string());
    dhcp_client.insert("readonly".to_string(), "true".to_string());
    devices.insert("dhcp-client".to_string(), dhcp_client);

    if gpu {
        let mut gpu0 = HashMap::new();
        gpu0.insert("type".to_string(), "gpu".to_string());
        gpu0.insert("gputype".to_string(), "physical".to_string());
        devices.insert("gpu0".to_string(), gpu0);
    }

    devices
}

/// Returns `"default"` plus any operator-configured extra profiles from
/// `driver_config.profiles`.
pub fn build_profiles(template: &DriverSandboxTemplate) -> Vec<String> {
    let mut profiles = vec!["default".to_string()];
    profiles.extend(struct_get_str_list(
        template.driver_config.as_ref(),
        "profiles",
    ));
    profiles
}

/// Where a sandbox lives in LXD: the network its NIC attaches to and the
/// storage pool its root disk is on.
///
/// The storage pool also places the supervisor and DHCP-client volumes, so
/// those auxiliary volumes land on the same pool as the rootfs they attach to
/// unless the operator pins them with `--supervisor-storage-pool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement<'a> {
    pub network: &'a str,
    pub storage_pool: &'a str,
}

impl<'a> Placement<'a> {
    /// The request's `driver_config.network` and `driver_config.storage_pool`,
    /// each falling back to the driver's configured default when unset, so
    /// users need not know how the LXD behind the gateway is laid out.
    pub fn resolve(
        template: &'a DriverSandboxTemplate,
        default_network: &'a str,
        default_storage_pool: &'a str,
    ) -> Self {
        let driver_config = template.driver_config.as_ref();
        Self {
            network: struct_get_str(driver_config, "network").unwrap_or(default_network),
            storage_pool: struct_get_str(driver_config, "storage_pool")
                .unwrap_or(default_storage_pool),
        }
    }
}

pub(crate) fn is_valid_label_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn struct_get_str<'a>(s: Option<&'a Struct>, key: &str) -> Option<&'a str> {
    match s?.fields.get(key)?.kind.as_ref()? {
        Kind::StringValue(v) => Some(v.as_str()),
        _ => None,
    }
}

fn struct_get_str_list(s: Option<&Struct>, key: &str) -> Vec<String> {
    let Some(Kind::ListValue(list)) = s.and_then(|s| s.fields.get(key)?.kind.as_ref()) else {
        return Vec::new();
    };
    list.values
        .iter()
        .filter_map(|v| match v.kind.as_ref() {
            Some(Kind::StringValue(s)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use lxd_client::LxdError;

    use super::*;

    const DEFAULTS: Placement<'static> = Placement {
        network: "lxdbr0",
        storage_pool: "default",
    };

    #[test]
    fn test_dhcp_client_volume_name() {
        assert_eq!(
            dhcp_client_volume_name("sha256:abc123def456"),
            "openshell-dhcp-client-abc123def456"
        );
        assert_eq!(
            dhcp_client_volume_name("abc123def456"),
            "openshell-dhcp-client-abc123def456"
        );
    }

    #[test]
    fn build_create_devices_omits_gpu_by_default() {
        let devices =
            build_create_devices(DEFAULTS, false, "default", "vol1", "default", "dhcp-vol1");

        assert!(!devices.contains_key("gpu0"));
        assert!(devices.contains_key("root"));
        assert!(devices.contains_key("eth0"));
        assert!(devices.contains_key("supervisor"));
        assert!(devices.contains_key("dhcp-client"));
    }

    #[test]
    fn build_create_devices_attaches_gpu_when_requested() {
        let devices =
            build_create_devices(DEFAULTS, true, "default", "vol1", "default", "dhcp-vol1");

        let gpu0 = devices.get("gpu0").expect("gpu0 device should be present");
        assert_eq!(gpu0.get("type"), Some(&"gpu".to_string()));
        assert_eq!(gpu0.get("gputype"), Some(&"physical".to_string()));
    }

    #[test]
    fn build_create_devices_attaches_supervisor_and_dhcp_client_volumes() {
        let digest = "sha256:11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        let sup_vol_name = supervisor_volume_name(digest);
        let dhcp_vol_name = dhcp_client_volume_name(digest);
        let devices = build_create_devices(
            DEFAULTS,
            false,
            "custom-pool",
            &sup_vol_name,
            "custom-dhcp-pool",
            &dhcp_vol_name,
        );

        let sup = devices
            .get("supervisor")
            .expect("supervisor device should be present");
        assert_eq!(sup.get("type"), Some(&"disk".to_string()));
        assert_eq!(sup.get("pool"), Some(&"custom-pool".to_string()));
        assert_eq!(sup.get("source"), Some(&sup_vol_name));
        assert_eq!(sup.get("path"), Some(&GUEST_SUPERVISOR_BIN_DIR.to_string()));
        assert_eq!(sup.get("readonly"), Some(&"true".to_string()));

        let dhcp = devices
            .get("dhcp-client")
            .expect("dhcp-client device should be present");
        assert_eq!(dhcp.get("type"), Some(&"disk".to_string()));
        assert_eq!(dhcp.get("pool"), Some(&"custom-dhcp-pool".to_string()));
        assert_eq!(dhcp.get("source"), Some(&dhcp_vol_name));
        assert_eq!(dhcp.get("path"), Some(&GUEST_DHCP_CLIENT_DIR.to_string()));
        assert_eq!(dhcp.get("readonly"), Some(&"true".to_string()));
    }

    #[test]
    fn guest_supervisor_paths_contract() {
        assert_eq!(GUEST_SUPERVISOR_BIN_DIR, "/opt/openshell/bin");
        assert_eq!(
            GUEST_SUPERVISOR_BIN_PATH,
            format!("{GUEST_SUPERVISOR_BIN_DIR}/openshell-sandbox")
        );
        assert_eq!(GUEST_DHCP_CLIENT_DIR, "/opt/openshell/net");
    }

    #[test]
    fn build_create_config_sets_ssh_socket_path() {
        let sandbox = DriverSandbox {
            id: "sb-123".to_string(),
            name: "test-sandbox".to_string(),
            ..Default::default()
        };
        let spec = DriverSandboxSpec::default();
        let template = DriverSandboxTemplate::default();

        let config = build_create_config(&sandbox, &spec, &template, "", false, 0)
            .expect("build_create_config should succeed");

        assert_eq!(
            config.get("environment.OPENSHELL_SSH_SOCKET_PATH"),
            Some(&GUEST_SSH_SOCKET_PATH.to_string())
        );
    }

    fn instance_with(status: &str, config: &[(&str, &str)]) -> Instance {
        Instance {
            name: "sb".to_string(),
            description: String::new(),
            status: status.to_string(),
            status_code: 0,
            architecture: String::new(),
            ephemeral: false,
            profiles: Vec::new(),
            config: config
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            devices: HashMap::new(),
            type_: "container".to_string(),
            project: "default".to_string(),
        }
    }

    /// The reason strings are a contract with the gateway, not cosmetic: it
    /// keys "is this transient?" and "may this be recovered at startup?" off
    /// these exact values.
    #[test]
    fn stopped_reason_distinguishes_death_from_requested_stop() {
        // Ran, then its init exited on its own → terminal ContainerExited.
        let died = instance_with("Stopped", &[("volatile.last_state.power", "STOPPED")]);
        let cond = ready_condition(&died);
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, CONDITION_EXITED);

        // The driver was asked to stop it → recoverable ContainerStopped.
        let stopped = instance_with(
            "Stopped",
            &[
                ("volatile.last_state.power", "STOPPED"),
                (KEY_STOP_INTENT, CONDITION_STOPPED),
            ],
        );
        assert_eq!(ready_condition(&stopped).reason, CONDITION_STOPPED);
    }

    /// A created-but-never-started instance is also `Stopped` in LXD. Reporting
    /// it as `ContainerExited` would put a sandbox that is merely mid-create
    /// into a terminal, sticky `Error` at the gateway.
    #[test]
    fn never_started_instance_is_transient_not_terminal() {
        let fresh = instance_with("Stopped", &[]);
        let cond = ready_condition(&fresh);
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, CONDITION_CREATED);
    }

    #[test]
    fn running_and_guest_signalled_ready_are_both_ready() {
        assert_eq!(
            ready_condition(&instance_with("Running", &[])).status,
            "True"
        );
        // LXD reports `Ready` once a guest signals over devlxd; without this
        // arm it fell through to `Unknown`.
        assert_eq!(ready_condition(&instance_with("Ready", &[])).status, "True");
    }

    #[test]
    fn transient_states_are_reported_with_transient_reasons() {
        assert_eq!(
            ready_condition(&instance_with("Starting", &[])).reason,
            CONDITION_STARTING
        );
        // An unrecognised status stays Unknown, which the gateway maps to
        // Provisioning rather than Error.
        assert_eq!(
            ready_condition(&instance_with("Weird", &[])).status,
            "Unknown"
        );
    }

    /// `ContainerPaused` is what upstream's Docker driver reports for a
    /// paused container (OpenShell v0.0.116
    /// `crates/openshell-driver-docker/src/lib.rs:3515`). It is not in the
    /// gateway's transient set, so a frozen sandbox surfaces as `Error`, the
    /// same as on Docker.
    #[test]
    fn frozen_is_reported_as_paused() {
        let cond = ready_condition(&instance_with("Frozen", &[]));
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, CONDITION_PAUSED);
    }

    /// The gateway shows the message next to the reason; an empty one leaves
    /// the user with `ContainerExited:` and nothing to go on.
    #[test]
    fn every_not_ready_state_explains_itself() {
        let ran = ("volatile.last_state.power", "STOPPED");
        for instance in [
            instance_with("Stopped", &[]),
            instance_with("Stopped", &[ran]),
            instance_with("Stopped", &[ran, (KEY_STOP_INTENT, CONDITION_STOPPED)]),
            instance_with("Starting", &[]),
            instance_with("Frozen", &[]),
            instance_with("Error", &[]),
            instance_with("Weird", &[]),
        ] {
            let cond = ready_condition(&instance);
            assert!(
                !cond.message.is_empty(),
                "{} {:?} has no message",
                instance.status,
                instance.config
            );
        }
        assert_eq!(ready_condition(&instance_with("Running", &[])).message, "");
    }

    #[test]
    fn exited_message_points_at_the_console_log() {
        let ran = ("volatile.last_state.power", "STOPPED");

        let cond = ready_condition(&instance_with("Stopped", &[ran]));
        assert!(
            cond.message.contains("`lxc console sb --show-log`"),
            "{}",
            cond.message
        );

        let in_project = Instance {
            project: "sandboxes".to_string(),
            ..instance_with("Stopped", &[ran])
        };
        let cond = ready_condition(&in_project);
        assert!(
            cond.message
                .contains("`lxc console sb --project sandboxes --show-log`"),
            "{}",
            cond.message
        );
    }

    #[test]
    fn lxd_error_status_is_reported_as_error() {
        let cond = ready_condition(&instance_with("Error", &[]));
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "Error");
    }

    /// Phase the OpenShell v0.0.116 gateway derives from a `Ready` condition
    /// (`crates/openshell-server/src/compute/mod.rs`, `derive_phase` and
    /// `is_terminal_failure_reason`, lines 4033-4131). Mirrored here so every
    /// reason the driver emits is checked against how the gateway reads it.
    fn v0_0_116_gateway_phase(cond: &DriverCondition) -> &'static str {
        const TRANSIENT_REASONS: &[&str] = &[
            "reconcilererror",
            "dependenciesnotready",
            "supervisornotconnected",
            "starting",
            "containerstarting",
            "containercreated",
            "healthcheckstarting",
            "inspectfailed",
        ];
        if cond.status.eq_ignore_ascii_case("true") {
            "Ready"
        } else if cond.status.eq_ignore_ascii_case("false") {
            if TRANSIENT_REASONS.contains(&cond.reason.to_ascii_lowercase().as_str()) {
                "Provisioning"
            } else {
                "Error"
            }
        } else {
            "Provisioning"
        }
    }

    /// The reason strings are consumed by the gateway, so pin the phase each
    /// observable instance state lands in. A mid-create sandbox must never
    /// read as `Error`; an exited or stopped one must not read as
    /// `Provisioning` (the gateway separately confirms `Stopping → Stopped`
    /// on `ContainerExited`/`ContainerStopped`, v0.0.116 `mod.rs:3877-3887`).
    #[test]
    fn every_reported_state_maps_to_the_intended_gateway_phase() {
        let ran = ("volatile.last_state.power", "STOPPED");
        let cases = [
            (instance_with("Running", &[]), "Ready"),
            (instance_with("Ready", &[]), "Ready"),
            (instance_with("Stopped", &[]), "Provisioning"),
            (instance_with("Starting", &[]), "Provisioning"),
            (instance_with("Weird", &[]), "Provisioning"),
            (instance_with("Stopped", &[ran]), "Error"),
            (
                instance_with("Stopped", &[ran, (KEY_STOP_INTENT, CONDITION_STOPPED)]),
                "Error",
            ),
            (instance_with("Frozen", &[]), "Error"),
            (instance_with("Error", &[]), "Error"),
        ];

        for (instance, expected) in cases {
            let cond = ready_condition(&instance);
            assert_eq!(cond.r#type, "Ready");
            assert_eq!(
                v0_0_116_gateway_phase(&cond),
                expected,
                "LXD status {:?} with config {:?} reported {cond:?}",
                instance.status,
                instance.config
            );
        }
    }

    #[test]
    fn observed_sandbox_carries_identity_and_one_ready_condition() {
        let instance = Instance {
            name: "sb-name".to_string(),
            ..instance_with(
                "Running",
                &[
                    (KEY_SANDBOX_ID, "sb-id"),
                    (KEY_NAMESPACE, "ns"),
                    (KEY_WORKSPACE, "ws"),
                ],
            )
        };

        let sandbox = instance_to_driver_sandbox(&instance);

        assert_eq!(sandbox.id, "sb-id");
        assert_eq!(sandbox.name, "sb-name");
        assert_eq!(sandbox.namespace, "ns");
        assert_eq!(sandbox.workspace, "ws");
        assert!(sandbox.spec.is_none(), "observed snapshots omit spec");

        let status = sandbox.status.expect("status is always reported");
        assert_eq!(status.sandbox_name, "sb-name");
        assert_eq!(status.instance_id, "sb-name");
        assert!(!status.deleting);
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].r#type, "Ready");
        assert_eq!(status.conditions[0].status, "True");
    }

    #[test]
    fn observed_sandbox_without_markers_has_empty_identity() {
        let sandbox = instance_to_driver_sandbox(&instance_with("Running", &[]));
        assert_eq!(sandbox.id, "");
        assert_eq!(sandbox.namespace, "");
        assert_eq!(sandbox.workspace, "");
    }

    fn string_value(s: &str) -> prost_types::Value {
        prost_types::Value {
            kind: Some(Kind::StringValue(s.to_string())),
        }
    }

    fn driver_config(fields: &[(&str, prost_types::Value)]) -> Option<Struct> {
        Some(Struct {
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        })
    }

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn identified_sandbox() -> DriverSandbox {
        DriverSandbox {
            id: "sb-123".to_string(),
            name: "test-sandbox".to_string(),
            namespace: "ns".to_string(),
            workspace: "ws".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn build_create_config_records_identity_and_init() {
        let config = build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            &DriverSandboxTemplate::default(),
            "",
            false,
            0,
        )
        .expect("build_create_config should succeed");

        assert_eq!(
            config.get(KEY_SANDBOX_ID).map(String::as_str),
            Some("sb-123")
        );
        assert_eq!(config.get(KEY_NAMESPACE).map(String::as_str), Some("ns"));
        assert_eq!(config.get(KEY_WORKSPACE).map(String::as_str), Some("ws"));
        // The image boots the init script as /sbin/init; low-level keys
        // would make restricted projects refuse the sandbox.
        assert!(
            !config.keys().any(|key| key.starts_with("raw.")),
            "{config:?}"
        );
        assert_eq!(
            config.get("security.nesting").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            config
                .get("environment.OPENSHELL_SANDBOX_ID")
                .map(String::as_str),
            Some("sb-123")
        );
        assert_eq!(
            config
                .get("environment.OPENSHELL_SANDBOX")
                .map(String::as_str),
            Some("test-sandbox")
        );
    }

    #[test]
    fn template_environment_overrides_spec_environment() {
        let spec = DriverSandboxSpec {
            environment: env(&[("SHARED", "from-spec"), ("SPEC_ONLY", "spec")]),
            ..Default::default()
        };
        let template = DriverSandboxTemplate {
            environment: env(&[("SHARED", "from-template"), ("TEMPLATE_ONLY", "template")]),
            ..Default::default()
        };

        let config = build_create_config(&identified_sandbox(), &spec, &template, "", false, 0)
            .expect("build_create_config should succeed");

        assert_eq!(
            config.get("environment.SHARED").map(String::as_str),
            Some("from-template")
        );
        assert_eq!(
            config.get("environment.SPEC_ONLY").map(String::as_str),
            Some("spec")
        );
        assert_eq!(
            config.get("environment.TEMPLATE_ONLY").map(String::as_str),
            Some("template")
        );
    }

    /// The supervisor trusts these variables to know which sandbox it is and
    /// where to reach the gateway; request-supplied environment must not be
    /// able to redirect it.
    #[test]
    fn driver_injected_environment_cannot_be_overridden_by_the_request() {
        let hostile = env(&[
            ("OPENSHELL_SANDBOX_ID", "someone-else"),
            ("OPENSHELL_SANDBOX", "someone-else"),
            ("OPENSHELL_SSH_SOCKET_PATH", "/tmp/evil.sock"),
            ("OPENSHELL_ENDPOINT", "http://attacker:1"),
            ("OPENSHELL_SANDBOX_TOKEN_FILE", "/tmp/evil.jwt"),
        ]);
        let spec = DriverSandboxSpec {
            environment: hostile.clone(),
            ..Default::default()
        };
        let template = DriverSandboxTemplate {
            environment: hostile,
            ..Default::default()
        };

        let config = build_create_config(
            &identified_sandbox(),
            &spec,
            &template,
            "http://10.0.0.1:17670",
            true,
            0,
        )
        .expect("build_create_config should succeed");

        let expected = [
            ("OPENSHELL_SANDBOX_ID", "sb-123"),
            ("OPENSHELL_SANDBOX", "test-sandbox"),
            ("OPENSHELL_SSH_SOCKET_PATH", GUEST_SSH_SOCKET_PATH),
            ("OPENSHELL_ENDPOINT", "http://10.0.0.1:17670"),
            ("OPENSHELL_SANDBOX_TOKEN_FILE", GUEST_SANDBOX_TOKEN_PATH),
        ];
        for (key, value) in expected {
            assert_eq!(
                config
                    .get(&format!("environment.{key}"))
                    .map(String::as_str),
                Some(value),
                "{key}"
            );
        }
    }

    fn decoded_main_process(config: &HashMap<String, String>) -> serde_json::Value {
        let encoded = config
            .get(&format!("environment.{ENV_MAIN_PROCESS_SPEC}"))
            .expect("main process spec is always set");
        serde_json::from_str(encoded).expect("main process spec is JSON")
    }

    #[test]
    fn requested_command_is_delivered_as_the_main_process_spec() {
        let spec = DriverSandboxSpec {
            command: vec![
                "sh".to_string(),
                "-lc".to_string(),
                "printf '%s\\n' \"quoted $VAR\" > /sandbox/out; echo ünïcode".to_string(),
            ],
            tty: false,
            ..Default::default()
        };

        let config = build_create_config(
            &identified_sandbox(),
            &spec,
            &DriverSandboxTemplate::default(),
            "",
            false,
            0,
        )
        .unwrap();

        assert_eq!(
            decoded_main_process(&config),
            serde_json::json!({
                "version": 1,
                "command": spec.command,
                "tty": false,
            })
        );
    }

    /// Upstream's supervisor rejects an empty command, and falls back to an
    /// interactive login shell when no spec is given; match that.
    #[test]
    fn empty_command_is_the_default_login_shell() {
        let config = build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            &DriverSandboxTemplate::default(),
            "",
            false,
            0,
        )
        .unwrap();

        assert_eq!(
            decoded_main_process(&config),
            serde_json::json!({
                "version": 1,
                "command": ["/bin/bash", "-l"],
                "tty": true,
            })
        );
    }

    #[test]
    fn request_environment_cannot_replace_the_main_process() {
        let spec = DriverSandboxSpec {
            command: vec!["true".to_string()],
            environment: env(&[(
                ENV_MAIN_PROCESS_SPEC,
                "{\"version\":1,\"command\":[\"evil\"]}",
            )]),
            ..Default::default()
        };
        let template = DriverSandboxTemplate {
            environment: env(&[(ENV_MAIN_PROCESS_SPEC, "{}")]),
            ..Default::default()
        };

        let config =
            build_create_config(&identified_sandbox(), &spec, &template, "", false, 0).unwrap();

        assert_eq!(
            decoded_main_process(&config)["command"],
            serde_json::json!(["true"])
        );
    }

    #[test]
    fn gateway_endpoint_is_only_injected_when_resolved() {
        let spec = DriverSandboxSpec {
            environment: env(&[("OPENSHELL_ENDPOINT", "http://from-gateway:17670")]),
            ..Default::default()
        };
        let template = DriverSandboxTemplate::default();

        let resolved = build_create_config(
            &identified_sandbox(),
            &spec,
            &template,
            "http://10.0.0.1:17670",
            false,
            0,
        )
        .expect("build_create_config should succeed");
        assert_eq!(
            resolved
                .get("environment.OPENSHELL_ENDPOINT")
                .map(String::as_str),
            Some("http://10.0.0.1:17670")
        );

        // Empty means "not resolved": the gateway-supplied value is kept.
        let unresolved = build_create_config(&identified_sandbox(), &spec, &template, "", false, 0)
            .expect("build_create_config should succeed");
        assert_eq!(
            unresolved
                .get("environment.OPENSHELL_ENDPOINT")
                .map(String::as_str),
            Some("http://from-gateway:17670")
        );
    }

    /// The token is delivered as a root-only file pushed before start. It
    /// must never be written into instance config, which any LXD API client
    /// with read access can see.
    #[test]
    fn sandbox_token_is_referenced_by_file_never_embedded() {
        let spec = DriverSandboxSpec {
            sandbox_token: "eyJhbGciOiJFZERTQSJ9.secret-token".to_string(),
            ..Default::default()
        };
        let template = DriverSandboxTemplate::default();

        let with_token = build_create_config(&identified_sandbox(), &spec, &template, "", true, 0)
            .expect("build_create_config should succeed");
        assert_eq!(
            with_token
                .get("environment.OPENSHELL_SANDBOX_TOKEN_FILE")
                .map(String::as_str),
            Some(GUEST_SANDBOX_TOKEN_PATH)
        );
        assert!(
            with_token.values().all(|v| !v.contains("secret-token")),
            "token leaked into instance config: {with_token:?}"
        );
        assert!(!with_token.contains_key("environment.OPENSHELL_SANDBOX_TOKEN"));

        let without_token =
            build_create_config(&identified_sandbox(), &spec, &template, "", false, 0)
                .expect("build_create_config should succeed");
        assert!(!without_token.contains_key("environment.OPENSHELL_SANDBOX_TOKEN_FILE"));
    }

    #[test]
    fn labels_are_namespaced_and_validated() {
        let template = DriverSandboxTemplate {
            labels: env(&[("team", "infra"), ("app.kubernetes.io_name", "agent")]),
            ..Default::default()
        };
        let config = build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            &template,
            "",
            false,
            0,
        )
        .expect("build_create_config should succeed");
        assert_eq!(
            config.get("user.openshell.label.team").map(String::as_str),
            Some("infra")
        );
        assert_eq!(
            config
                .get("user.openshell.label.app.kubernetes.io_name")
                .map(String::as_str),
            Some("agent")
        );

        let invalid = DriverSandboxTemplate {
            labels: env(&[("has/slash", "x")]),
            ..Default::default()
        };
        let err = build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            &invalid,
            "",
            false,
            0,
        )
        .expect_err("invalid label key should be rejected");
        assert!(matches!(err, DriverError::InvalidArgument(_)));
    }

    #[test]
    fn label_key_charset() {
        for valid in ["a", "A-Z_0.9", "team.example-key_1"] {
            assert!(is_valid_label_key(valid), "{valid:?}");
        }
        for invalid in ["", "with space", "slash/key", "colon:key", "ünïcode", "a=b"] {
            assert!(!is_valid_label_key(invalid), "{invalid:?}");
        }
    }

    fn resources(
        cpu_request: &str,
        cpu_limit: &str,
        memory_request: &str,
        memory_limit: &str,
    ) -> DriverSandboxTemplate {
        DriverSandboxTemplate {
            resources: Some(computev1::pb::DriverResourceRequirements {
                cpu_request: cpu_request.to_string(),
                cpu_limit: cpu_limit.to_string(),
                memory_request: memory_request.to_string(),
                memory_limit: memory_limit.to_string(),
            }),
            ..Default::default()
        }
    }

    fn config_for(
        template: &DriverSandboxTemplate,
    ) -> Result<HashMap<String, String>, DriverError> {
        build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            template,
            "",
            false,
            0,
        )
    }

    #[test]
    fn resource_limits_prefer_limit_over_request() {
        let config = config_for(&resources("1", "3", "256Mi", "1Gi")).unwrap();
        assert_eq!(config.get("limits.cpu").map(String::as_str), Some("3"));
        assert_eq!(
            config.get("limits.memory").map(String::as_str),
            Some("1GiB")
        );
    }

    /// LXD has no soft request, so a request alone becomes the hard limit.
    #[test]
    fn resource_request_is_enforced_when_no_limit_is_given() {
        let config = config_for(&resources("500m", "", "512Mi", "")).unwrap();
        assert_eq!(config.get("limits.cpu").map(String::as_str), Some("1"));
        assert_eq!(
            config.get("limits.memory").map(String::as_str),
            Some("512MiB")
        );
    }

    #[test]
    fn no_resources_means_no_cpu_or_memory_limits() {
        let config = config_for(&DriverSandboxTemplate::default()).unwrap();
        assert!(!config.contains_key("limits.cpu"));
        assert!(!config.contains_key("limits.memory"));

        let empty = config_for(&resources("", "", "", "")).unwrap();
        assert!(!empty.contains_key("limits.cpu"));
        assert!(!empty.contains_key("limits.memory"));
    }

    #[test]
    fn invalid_resource_quantities_are_rejected() {
        for template in [
            resources("", "lots", "", ""),
            resources("", "0", "", ""),
            resources("", "", "", "12Qi"),
        ] {
            let err = config_for(&template).expect_err("invalid quantity should be rejected");
            assert!(
                matches!(err, DriverError::Lxd(LxdError::InvalidQuantity { .. })),
                "{err:?}"
            );
        }
    }

    #[test]
    fn max_processes_override_accepts_numbers_and_numeric_strings() {
        let as_string = DriverSandboxTemplate {
            driver_config: driver_config(&[("max_processes", string_value("128"))]),
            ..Default::default()
        };
        assert_eq!(max_processes(&as_string), Some(128));

        // 0 lifts the limit for this sandbox even when the driver has a default.
        let zero = DriverSandboxTemplate {
            driver_config: driver_config(&[(
                "max_processes",
                prost_types::Value {
                    kind: Some(Kind::NumberValue(0.0)),
                },
            )]),
            ..Default::default()
        };
        let config = build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            &zero,
            "",
            false,
            4096,
        )
        .unwrap();
        assert!(!config.contains_key("limits.processes"));
    }

    #[test]
    fn unusable_max_processes_override_falls_back_to_default() {
        for value in [
            prost_types::Value {
                kind: Some(Kind::NumberValue(-1.0)),
            },
            string_value("many"),
            prost_types::Value {
                kind: Some(Kind::BoolValue(true)),
            },
        ] {
            let template = DriverSandboxTemplate {
                driver_config: driver_config(&[("max_processes", value)]),
                ..Default::default()
            };
            let config = build_create_config(
                &identified_sandbox(),
                &DriverSandboxSpec::default(),
                &template,
                "",
                false,
                4096,
            )
            .unwrap();
            assert_eq!(
                config.get("limits.processes").map(String::as_str),
                Some("4096")
            );
        }
    }

    #[test]
    fn placement_defaults_and_override() {
        let defaults = DriverSandboxTemplate::default();
        assert_eq!(
            Placement::resolve(&defaults, "ovn0", "local"),
            Placement {
                network: "ovn0",
                storage_pool: "local",
            }
        );

        let custom = DriverSandboxTemplate {
            driver_config: driver_config(&[
                ("network", string_value("sandboxbr0")),
                ("storage_pool", string_value("fast")),
            ]),
            ..Default::default()
        };
        assert_eq!(
            Placement::resolve(&custom, "ovn0", "local"),
            Placement {
                network: "sandboxbr0",
                storage_pool: "fast",
            }
        );

        // Only one of them set: the other keeps the driver's default.
        let pool_only = DriverSandboxTemplate {
            driver_config: driver_config(&[("storage_pool", string_value("remote"))]),
            ..Default::default()
        };
        assert_eq!(
            Placement::resolve(&pool_only, "ovn0", "local"),
            Placement {
                network: "ovn0",
                storage_pool: "remote",
            }
        );

        // Wrong types are ignored rather than half-applied.
        let wrong_types = DriverSandboxTemplate {
            driver_config: driver_config(&[
                (
                    "network",
                    prost_types::Value {
                        kind: Some(Kind::NumberValue(1.0)),
                    },
                ),
                (
                    "storage_pool",
                    prost_types::Value {
                        kind: Some(Kind::BoolValue(true)),
                    },
                ),
            ]),
            ..Default::default()
        };
        assert_eq!(
            Placement::resolve(&wrong_types, "ovn0", "local"),
            Placement {
                network: "ovn0",
                storage_pool: "local",
            }
        );
    }

    #[test]
    fn devices_follow_placement() {
        let placement = Placement {
            network: "sandboxbr0",
            storage_pool: "fast",
        };

        let devices = build_create_devices(placement, false, "fast", "sup", "fast", "dhcp");

        let root = devices.get("root").expect("root device");
        assert_eq!(root.get("pool").map(String::as_str), Some("fast"));
        assert_eq!(root.get("path").map(String::as_str), Some("/"));
        let eth0 = devices.get("eth0").expect("eth0 device");
        assert_eq!(eth0.get("type").map(String::as_str), Some("nic"));
        assert_eq!(eth0.get("network").map(String::as_str), Some("sandboxbr0"));
    }

    #[test]
    fn profiles_always_start_with_default() {
        assert_eq!(
            build_profiles(&DriverSandboxTemplate::default()),
            vec!["default".to_string()]
        );

        let template = DriverSandboxTemplate {
            driver_config: driver_config(&[(
                "profiles",
                prost_types::Value {
                    kind: Some(Kind::ListValue(prost_types::ListValue {
                        values: vec![
                            string_value("gpu"),
                            prost_types::Value {
                                kind: Some(Kind::NumberValue(7.0)),
                            },
                            string_value("audit"),
                        ],
                    })),
                },
            )]),
            ..Default::default()
        };
        assert_eq!(
            build_profiles(&template),
            vec![
                "default".to_string(),
                "gpu".to_string(),
                "audit".to_string()
            ]
        );
    }

    #[test]
    fn volume_names_are_digest_keyed() {
        let digest = "sha256:0123abcd";
        assert_eq!(
            supervisor_volume_name(digest),
            "openshell-supervisor-0123abcd"
        );
        assert_eq!(
            supervisor_volume_name("0123abcd"),
            supervisor_volume_name(digest)
        );
    }

    #[test]
    fn build_create_config_sets_default_pid_limit() {
        let sandbox = DriverSandbox::default();
        let spec = DriverSandboxSpec::default();
        let template = DriverSandboxTemplate::default();

        let config = build_create_config(&sandbox, &spec, &template, "", false, 4096)
            .expect("build_create_config should succeed");
        assert_eq!(config.get("limits.processes"), Some(&"4096".to_string()));

        // 0 means "leave pids.max alone".
        let unlimited = build_create_config(&sandbox, &spec, &template, "", false, 0)
            .expect("build_create_config should succeed");
        assert!(!unlimited.contains_key("limits.processes"));
    }

    #[test]
    fn driver_config_overrides_pid_limit() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "max_processes".to_string(),
            prost_types::Value {
                kind: Some(Kind::NumberValue(256.0)),
            },
        );
        let template = DriverSandboxTemplate {
            driver_config: Some(Struct { fields }),
            ..Default::default()
        };

        let config = build_create_config(
            &DriverSandbox::default(),
            &DriverSandboxSpec::default(),
            &template,
            "",
            false,
            4096,
        )
        .expect("build_create_config should succeed");

        assert_eq!(config.get("limits.processes"), Some(&"256".to_string()));
    }

    #[test]
    fn max_processes_validation() {
        use prost_types::Value;
        use std::collections::BTreeMap;

        let template_with_max_processes = |kind: Kind| DriverSandboxTemplate {
            driver_config: Some(Struct {
                fields: BTreeMap::from([("max_processes".to_string(), Value { kind: Some(kind) })]),
            }),
            ..Default::default()
        };

        // Whole, non-negative numbers and valid numeric strings are accepted
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(512.0))),
            Some(512)
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(0.0))),
            Some(0)
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::StringValue(
                "256".to_string()
            ))),
            Some(256)
        );

        // Fractional numbers must not be cast to integers (e.g. 0.5 != 0)
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(0.5))),
            None
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(1.5))),
            None
        );

        // Negative numbers must not be accepted
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(-1.0))),
            None
        );

        // Out of range or non-finite numbers must not be accepted
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(
                u32::MAX as f64 + 1000.0
            ))),
            None
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(f64::NAN))),
            None
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(
                f64::INFINITY
            ))),
            None
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::NumberValue(
                f64::NEG_INFINITY
            ))),
            None
        );

        // Invalid strings must not be treated as valid overrides
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::StringValue(
                "abc".to_string()
            ))),
            None
        );
        assert_eq!(
            max_processes(&template_with_max_processes(Kind::StringValue(
                "-5".to_string()
            ))),
            None
        );

        // Empty template yields None
        assert_eq!(max_processes(&DriverSandboxTemplate::default()), None);
    }
}
