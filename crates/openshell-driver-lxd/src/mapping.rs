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

/// Which half of a sandbox an instance is.
///
/// A sandbox is two LXD instances from OpenShell v0.1.0 on, and only the
/// workload is a sandbox as far as the gateway is concerned. Every driver
/// query filters the companion out by this key, so a caller still sees one
/// sandbox per sandbox.
pub(crate) const KEY_ROLE: &str = "user.openshell.role";
pub(crate) const ROLE_WORKLOAD: &str = "workload";
pub(crate) const ROLE_SUPERVISOR: &str = "supervisor";

/// On a companion, the workload instance it supervises.
pub(crate) const KEY_WORKLOAD_INSTANCE: &str = "user.openshell.workload_instance";

/// Environment variable the init script reads to know which half it is
/// booting. Driver-private: it is not part of any OpenShell contract, and the
/// workload container never carries it.
pub(crate) const ENV_ROLE: &str = "OPENSHELL_ROLE";

/// What a sandbox was created with, recorded so a later start can rebuild the
/// same launch artifacts without the create request.
///
/// Start-from-stopped gets a fresh session and therefore a fresh descriptor,
/// bootstrap and fence, all of which describe the instance as it was created.
/// The gateway does not resend the create request, so the driver keeps what it
/// cannot otherwise recover.
pub(crate) const KEY_NETWORK: &str = "user.openshell.network";
pub(crate) const KEY_NETWORK_TYPE: &str = "user.openshell.network_type";
pub(crate) const KEY_EGRESS_ACL: &str = "user.openshell.egress_acl";
pub(crate) const KEY_IMAGE_ALIAS: &str = "user.openshell.image_alias";

/// Whether the caller supplied `template.driver_config` when this sandbox was
/// created, as `"true"` or `"false"`.
///
/// Upstream calls this provenance and records it the same way
/// (`openshell.ai/caller-driver-config-used`, on the container), because the
/// admission policy can be turned off after a sandbox exists and the config
/// it was created with outlives the flag that allowed it. Without the record
/// there is nothing to check at start but the flag's current value, which
/// says nothing about what this sandbox is already running with.
pub(crate) const KEY_CALLER_DRIVER_CONFIG: &str = "user.openshell.caller_driver_config_used";

/// The workload-identity selectors the gateway admitted, verbatim.
///
/// `StartSandboxRequest` carries no template, so a start has no way to learn
/// that the policy asked for `run_as_user: appuser`. Re-resolving against the
/// image with no selectors would answer a different question — "who does this
/// image suggest?" rather than "who was this sandbox admitted to run as?" —
/// and quietly run the workload as somebody else from its second boot on.
pub(crate) const KEY_WORKLOAD_USER: &str = "user.openshell.workload_user";
pub(crate) const KEY_WORKLOAD_GROUP: &str = "user.openshell.workload_group";

/// The declared environment, as JSON, for the workload's processes only.
///
/// It cannot be read back off the instance's own `environment.*` keys: those
/// also carry the plumbing the in-workload boundary needs and the workload
/// must not see.
pub(crate) const KEY_CHILD_ENV: &str = "user.openshell.child_env";

/// Suffix the companion's instance name adds to the sandbox's.
pub(crate) const SUPERVISOR_SUFFIX: &str = "-supervisor";

/// Naming convention for a sandbox's supervisor companion: `<name>-supervisor`.
pub(crate) fn supervisor_instance_name(sandbox_name: &str) -> String {
    format!("{sandbox_name}{SUPERVISOR_SUFFIX}")
}

/// The longest sandbox name the driver accepts.
///
/// LXD's own limit is 63 characters, but a sandbox is two instances and the
/// companion's name is the sandbox's plus [`SUPERVISOR_SUFFIX`]. Validating
/// against 63 would admit a name whose companion LXD then rejects — after the
/// image is resolved, the volumes are provisioned and the workload is created,
/// so the caller's error arrives late and as LXD's rather than the driver's.
pub(crate) const MAX_SANDBOX_NAME_LEN: usize = 63 - SUPERVISOR_SUFFIX.len();

/// Whether `name` is usable as an LXD instance name.
///
/// LXD's own rule: ASCII letters, digits and dashes, not starting with a
/// digit or a dash, and no longer than [`MAX_SANDBOX_NAME_LEN`]. The driver
/// checks it rather than letting LXD reject it later, because the name is
/// interpolated into the REST paths this driver builds — a name carrying
/// `?project=` would otherwise add a query parameter ahead of the driver's
/// own, and LXD honours the first one, which puts the operation in another
/// project entirely. Percent-encoding in the client closes that too; refusing
/// the name here means a caller gets a clear error instead of a mangled
/// instance name.
pub(crate) fn is_valid_instance_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SANDBOX_NAME_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && !name.ends_with('-')
}

/// Whether `instance` really is `sandbox_name`'s companion.
///
/// [`supervisor_instance_name`] is a name a caller can ask for. Sandbox names
/// come from the gateway, which passes the user's own
/// (`Sandbox::object_name()`), so a sandbox called `foo-supervisor` owns the
/// instance that `foo`'s companion would be named after. Acting on that name
/// alone — stopping it, deleting it, folding its state into a Ready condition
/// — would be acting on someone else's sandbox. Every companion the driver
/// creates records both its role and the workload it belongs to, and nothing
/// without those markers is this sandbox's to touch.
pub(crate) fn is_companion_of(
    instance: &Instance,
    sandbox_name: &str,
    sandbox_id: Option<&str>,
) -> bool {
    let role_and_name = instance.config.get(KEY_ROLE).map(String::as_str) == Some(ROLE_SUPERVISOR)
        && instance
            .config
            .get(KEY_WORKLOAD_INSTANCE)
            .map(String::as_str)
            == Some(sandbox_name);
    // The name identifies the *generation* only when the id agrees. A sandbox
    // that was deleted and created again under the same name can leave the
    // previous generation's companion behind — a delete whose companion stop
    // failed does exactly that — and by role and name alone that companion
    // belongs to the new sandbox, which would fold a stranger's state into its
    // readiness and hand it this sandbox's stop and delete. Callers that know
    // which generation they are asking about pass its id; those that only have
    // a name pass `None` and get the weaker answer they asked for.
    role_and_name
        && match sandbox_id {
            Some(id) => instance.config.get(KEY_SANDBOX_ID).map(String::as_str) == Some(id),
            None => true,
        }
}

/// Identifies the guest-side Unix socket path where the supervisor binds its
/// SSH relay listener. The supervisor reads it via `OPENSHELL_SSH_SOCKET_PATH`.
pub(crate) const GUEST_SSH_SOCKET_PATH: &str = "/run/openshell/ssh.sock";

/// Environment variable carrying the sandbox's canonical main process to the
/// supervisor (OpenShell v0.0.116 `openshell-core::sandbox_env::MAIN_PROCESS_SPEC`).
pub(crate) const ENV_MAIN_PROCESS_SPEC: &str = "OPENSHELL_MAIN_PROCESS_SPEC";

/// Version of the [`ENV_MAIN_PROCESS_SPEC`] encoding the supervisor accepts.
const MAIN_PROCESS_SPEC_VERSION: u32 = 1;

/// Encodes the sandbox's main process for [`ENV_MAIN_PROCESS_SPEC`]:
/// `{"version":1,"command":[...],"tty":bool,"await_main_process_attachment":bool}`,
/// the JSON form upstream's `MainProcessConfig` decodes.
///
/// An empty command means the supervisor's default interactive shell — the
/// same fallback upstream applies — because the supervisor rejects a spec
/// whose command is empty. `await_main_process_attachment` (OpenShell
/// v0.1.0-pre.1) tells the supervisor that the creating client will attach to
/// the command, and is only passed with a requested command, as upstream's
/// `MainProcessConfig::from_driver_spec` does; the v0.0.116 supervisor ignores
/// the field.
pub fn main_process_spec(spec: &DriverSandboxSpec) -> String {
    let (command, tty, await_attachment) = if spec.command.is_empty() {
        (vec!["/bin/bash".to_string(), "-l".to_string()], true, false)
    } else {
        (
            spec.command.clone(),
            spec.tty,
            spec.await_main_process_attachment,
        )
    };
    serde_json::json!({
        "version": MAIN_PROCESS_SPEC_VERSION,
        "command": command,
        "tty": tty,
        "await_main_process_attachment": await_attachment,
    })
    .to_string()
}

/// Guest-side paths of the TLS materials the supervisor connects to the
/// gateway with — the paths upstream's `openshell-core::driver_utils` gives
/// every driver (OpenShell v0.0.116), so the layout matches the in-tree ones.
pub(crate) const GUEST_TLS_CA_PATH: &str = "/etc/openshell/tls/client/ca.crt";
pub(crate) const GUEST_TLS_CERT_PATH: &str = "/etc/openshell/tls/client/tls.crt";
pub(crate) const GUEST_TLS_KEY_PATH: &str = "/etc/openshell/tls/client/tls.key";

/// Points the supervisor at the TLS materials pushed to [`GUEST_TLS_CA_PATH`],
/// [`GUEST_TLS_CERT_PATH`] and [`GUEST_TLS_KEY_PATH`] (upstream's
/// `OPENSHELL_TLS_CA`, `OPENSHELL_TLS_CERT` and `OPENSHELL_TLS_KEY`).
pub fn insert_guest_tls_environment(config: &mut HashMap<String, String>) {
    for (name, path) in [
        ("OPENSHELL_TLS_CA", GUEST_TLS_CA_PATH),
        ("OPENSHELL_TLS_CERT", GUEST_TLS_CERT_PATH),
        ("OPENSHELL_TLS_KEY", GUEST_TLS_KEY_PATH),
    ] {
        config.insert(format!("{ENV_PREFIX}{name}"), path.to_string());
    }
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
///
/// For a sandbox found already stopped. Use
/// [`instance_to_driver_sandbox_live`] when a lifecycle event announced the
/// stop as it happened.
pub fn instance_to_driver_sandbox(instance: &Instance) -> DriverSandbox {
    to_driver_sandbox(instance, StopSeen::Discovered)
}

/// Maps an [`Instance`] whose stop the driver saw announced by a live LXD
/// lifecycle event.
///
/// Such a stop cannot be LXD going down with the daemon or the host: the
/// event proves LXD is up to send it. A `volatile.last_state.power` still
/// recorded as `RUNNING` is then the tail of a stop LXD is finishing, not a
/// runtime restart (see [`StopSeen`]).
pub(crate) fn instance_to_driver_sandbox_live(instance: &Instance) -> DriverSandbox {
    to_driver_sandbox(instance, StopSeen::Live)
}

/// How the driver learned that a sandbox is stopped, which decides whether
/// [`CONDITION_RUNTIME_RESTART`] is reachable at all.
///
/// LXD clears `volatile.last_state.power` asynchronously — about 0.7s after
/// the init exits on LXD 6.9 — so that key alone cannot tell a sandbox LXD
/// stopped from one whose init just exited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopSeen {
    /// Found already stopped, by a poll or a reconcile: LXD may have stopped
    /// it with the daemon or the host, so the recorded power is trusted.
    Discovered,
    /// Announced by a live lifecycle event, so LXD is up and the stop was the
    /// init exiting or a stop that was asked for.
    Live,
}

/// Whether LXD, rather than the sandbox's own init, looks to have stopped
/// `instance`. Only meaningful for a sandbox found already stopped; the
/// caller confirms it by re-reading, since the marker is cleared late.
pub(crate) fn stopped_by_the_runtime(instance: &Instance) -> bool {
    instance.status == "Stopped"
        && !instance.config.contains_key(KEY_STOP_INTENT)
        && instance
            .config
            .get(KEY_LAST_POWER)
            .is_some_and(|power| power == "RUNNING")
}

fn to_driver_sandbox(instance: &Instance, stop_seen: StopSeen) -> DriverSandbox {
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
            name: instance.name.clone(),
            instance_id: instance.name.clone(),
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![ready_condition(instance, stop_seen)],
            deleting: false,
            // Both are declared by the v0.1.0-pre.11 contract but not read by
            // the gateway yet: it takes the workload identity and the fence
            // from the supervisor's own attach, not from this snapshot.
            resolved_identity: None,
            fence_evidence: None,
        }),
    }
}

/// Ready-condition reason when a sandbox's init exited on its own — an
/// ordinary application exit or a crash.
///
/// Terminal: the gateway deliberately does not relaunch these at startup, so a
/// genuine failure keeps its error signal.
pub(crate) const CONDITION_EXITED: &str = "ContainerExited";

/// Ready-condition reason when the runtime stopped a sandbox that was running
/// — LXD shutting down with the daemon or the host — rather than its init
/// exiting. The gateway treats it as terminal like [`CONDITION_EXITED`]. From
/// OpenShell v0.1.0-pre.1 it restarts sandboxes with this reason at startup,
/// but only for drivers that report `gateway_manages_lifecycle`, which this
/// driver does not.
pub(crate) const CONDITION_RUNTIME_RESTART: &str = "ContainerRuntimeRestart";

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
fn ready_condition(instance: &Instance, stop_seen: StopSeen) -> DriverCondition {
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
            } else if stop_seen == StopSeen::Discovered && stopped_by_the_runtime(instance) {
                // LXD records RUNNING when it stops a running instance on its
                // own shutdown, so it can bring it back; an init that exits
                // records STOPPED — but only once LXD has finished the stop,
                // so this is reached for a sandbox found already stopped and
                // confirmed by a re-read, never off a live lifecycle event.
                (
                    "False",
                    CONDITION_RUNTIME_RESTART,
                    "LXD stopped the running sandbox instance (daemon or host shutdown) and \
                     has not started it again"
                        .to_string(),
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
        // Left unset, as it was when this was a string: LXD records when an
        // instance last changed state, not when this derived Ready condition
        // did, and reporting the one as the other would date every condition
        // to the sandbox's last start.
        transition_time: None,
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

/// The declared environment the workload's own processes get.
///
/// `template.environment` wins over `spec.environment` on a key collision, as
/// it does everywhere else. This is handed to the in-workload boundary in its
/// bootstrap rather than set on the container: the boundary injects it into
/// the processes it starts, and keeping it out of the container's environment
/// keeps it out of the boundary's own.
pub(crate) fn workload_child_env(
    spec: &DriverSandboxSpec,
    template: &DriverSandboxTemplate,
) -> HashMap<String, String> {
    let mut env = spec.environment.clone();
    env.extend(template.environment.clone());
    env
}

/// The workload container: the user's image, the boundary binary, and nothing
/// that belongs to the trusted half.
///
/// Under RFC 0012 this container runs `openshell-sandbox`, which takes a
/// single `--bootstrap` file and reads no OpenShell environment at all. The
/// gateway endpoint, the main-process spec, the SSH relay socket and the
/// gateway credentials are the supervisor companion's, and deliberately do not
/// appear here — the workload is the untrusted half.
pub fn build_create_config(
    sandbox: &DriverSandbox,
    spec: &DriverSandboxSpec,
    template: &DriverSandboxTemplate,
    default_max_processes: u32,
    log_level: &str,
) -> Result<HashMap<String, String>, DriverError> {
    let mut config = HashMap::new();

    config.insert(KEY_SANDBOX_ID.to_string(), sandbox.id.clone());
    config.insert(KEY_NAMESPACE.to_string(), sandbox.namespace.clone());
    config.insert(KEY_WORKSPACE.to_string(), sandbox.workspace.clone());
    config.insert(KEY_ROLE.to_string(), ROLE_WORKLOAD.to_string());
    // The guest API is a host daemon surface the workload has no use for: it
    // exposes the instance's own `user.*` configuration and lets a guest push
    // state back. The companion keeps it; the untrusted half does not get it.
    config.insert("security.devlxd".to_string(), "false".to_string());
    // Pinned on the instance, not merely refused on the profiles a caller
    // names. Instance config overrides profile config, and a profile the
    // driver does not scan — the project's `default`, which every instance
    // gets — could otherwise carry either of these and silently take away the
    // user namespace the whole confinement rests on. The driver turns nesting
    // back on below when `--sandbox-nesting` asks for it; privileged has no
    // such switch.
    config.insert("security.privileged".to_string(), "false".to_string());
    config.insert("security.nesting".to_string(), "false".to_string());
    // The init script uses this to set the container's hostname; the boundary
    // itself takes everything it needs from its bootstrap file.
    config.insert(
        format!("{ENV_PREFIX}OPENSHELL_SANDBOX_ID"),
        sandbox.id.clone(),
    );
    config.insert(
        format!("{ENV_PREFIX}OPENSHELL_LOG_LEVEL"),
        log_level.to_string(),
    );

    // Recorded so a later start resolves the identity the gateway admitted,
    // not whatever the image would suggest on its own. Empty selectors are
    // left out: absent and "unset" mean the same thing to the resolver.
    if let Some(identity) = spec.workload_identity.as_ref() {
        for (key, value) in [
            (KEY_WORKLOAD_USER, identity.user.trim()),
            (KEY_WORKLOAD_GROUP, identity.group.trim()),
        ] {
            if !value.is_empty() {
                config.insert(key.to_string(), value.to_string());
            }
        }
    }

    config.insert(
        KEY_CALLER_DRIVER_CONFIG.to_string(),
        template
            .driver_config
            .as_ref()
            .is_some_and(|config| !config.fields.is_empty())
            .to_string(),
    );

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

/// The supervisor companion container: the trusted half of a sandbox.
///
/// It runs `openshell-supervisor`, holds the gateway credentials and the
/// canonical main-process spec, and dials the workload's boundary over the
/// transport its backend descriptor names. The descriptor is pushed later, by
/// the driver, because it carries an address DHCP only assigns once the
/// workload is up.
pub fn build_supervisor_config(
    sandbox: &DriverSandbox,
    spec: &DriverSandboxSpec,
    gateway_endpoint: &str,
    log_level: &str,
) -> HashMap<String, String> {
    let mut config = HashMap::new();
    config.insert(KEY_SANDBOX_ID.to_string(), sandbox.id.clone());
    config.insert(KEY_NAMESPACE.to_string(), sandbox.namespace.clone());
    config.insert(KEY_WORKSPACE.to_string(), sandbox.workspace.clone());
    config.insert(KEY_ROLE.to_string(), ROLE_SUPERVISOR.to_string());
    config.insert(KEY_WORKLOAD_INSTANCE.to_string(), sandbox.name.clone());
    // Which half the init script is booting. The two take different binaries
    // and different arguments, and neither accepts the other's; the workload
    // leaves this unset and the script's default branch is its one.
    config.insert(
        format!("{ENV_PREFIX}{ENV_ROLE}"),
        ROLE_SUPERVISOR.to_string(),
    );
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
    config.insert(
        format!("{ENV_PREFIX}OPENSHELL_LOG_LEVEL"),
        log_level.to_string(),
    );
    // Told out of band rather than read from the descriptor: upstream verifies
    // the descriptor *against* the admitted backend, and taking both from one
    // file would make that check self-referential.
    config.insert(
        format!(
            "{ENV_PREFIX}{}",
            crate::isolation::ENV_ADMITTED_ISOLATION_BACKEND
        ),
        crate::isolation::BACKEND_NAME.to_string(),
    );
    if !gateway_endpoint.is_empty() {
        config.insert(
            format!("{ENV_PREFIX}OPENSHELL_ENDPOINT"),
            gateway_endpoint.to_string(),
        );
    }
    config
}

/// Devices for the supervisor companion.
///
/// It sits on the same network, behind the same egress ACL, as the workload it
/// supervises: it has to reach both the gateway and the workload's boundary,
/// and it is no more entitled to the LAN than the workload is.
pub fn build_supervisor_devices(
    placement: Placement<'_>,
    acls: &[&str],
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

    devices.insert("eth0".to_string(), sandbox_nic(placement.network, acls));

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

    devices
}

/// A sandbox NIC on `network`, fenced by `egress_acl`.
///
/// The default actions are what make the ACL a fence: everything the rules do
/// not name is rejected, in both directions.
fn sandbox_nic(network: &str, acls: &[&str]) -> HashMap<String, String> {
    let mut nic = HashMap::new();
    nic.insert("type".to_string(), "nic".to_string());
    nic.insert("network".to_string(), network.to_string());
    let acls: Vec<&str> = acls.iter().copied().filter(|acl| !acl.is_empty()).collect();
    if !acls.is_empty() {
        nic.insert("security.acls".to_string(), acls.join(","));
        nic.insert(
            "security.acls.default.egress.action".to_string(),
            "reject".to_string(),
        );
        nic.insert(
            "security.acls.default.ingress.action".to_string(),
            "reject".to_string(),
        );
    }
    nic
}

/// Folds the companion's state into the sandbox's own Ready condition.
///
/// A sandbox is only as ready as its trusted half: a workload whose companion
/// is missing, stopped or erroring has no supervision, whatever the workload
/// container itself reports. Reporting the companion's trouble as the
/// sandbox's is what lets an operator see it at all — the companion is hidden
/// from every other driver query.
///
/// It only ever *downgrades*, and never over a workload that is already
/// saying why it is not running: that reason is the specific one, and it
/// carries the console log that explains it, while the companion's is the
/// same event seen one step removed.
pub fn aggregate_companion_status(sandbox: &mut DriverSandbox, companion: Option<&Instance>) {
    let Some(status) = sandbox.status.as_mut() else {
        return;
    };
    if workload_explains_itself(status) {
        return;
    }
    let ready = status
        .conditions
        .iter()
        .any(|c| c.r#type == "Ready" && c.status == "True");
    let downgrade = |reason: &str, message: String| DriverCondition {
        r#type: "Ready".to_string(),
        status: "False".to_string(),
        reason: reason.to_string(),
        message,
        transition_time: None,
    };

    let Some(companion) = companion else {
        // Only meaningful while the workload claims to be ready: a workload
        // that is already reporting why it is not running should keep saying
        // so, and a sandbox mid-creation has no companion yet.
        if ready {
            status.conditions = vec![downgrade(
                CONDITION_STARTING,
                "supervisor companion instance does not exist".to_string(),
            )];
        }
        return;
    };

    if companion.status.eq_ignore_ascii_case("Error") {
        if !ready {
            return;
        }
        status.conditions = vec![downgrade(
            "ContainerError",
            format!(
                "supervisor companion instance is in error state: {}",
                companion.status
            ),
        )];
    } else if companion.status.eq_ignore_ascii_case("Stopped") {
        if !companion.config.contains_key(KEY_LAST_POWER) {
            if ready {
                status.conditions = vec![downgrade(
                    CONDITION_STARTING,
                    "supervisor companion has not started yet".to_string(),
                )];
            }
        } else if companion.config.contains_key(KEY_STOP_INTENT) {
            // A *running* workload whose companion is deliberately stopped is
            // a sandbox being started: the driver starts the workload first,
            // waits for its address, and only then starts the companion. That
            // is transient, not a stop — reporting it as one would tell the
            // gateway a sandbox it just started is down.
            if ready {
                status.conditions = vec![downgrade(
                    CONDITION_STARTING,
                    "supervisor companion has not been started yet".to_string(),
                )];
            }
        } else if ready {
            status.conditions = vec![downgrade(
                CONDITION_EXITED,
                "supervisor companion stopped unexpectedly".to_string(),
            )];
        }
    } else if !companion.status.eq_ignore_ascii_case("Running") && ready {
        status.conditions = vec![downgrade(
            CONDITION_STARTING,
            format!("supervisor companion is not ready: {}", companion.status),
        )];
    }
}

/// Whether the workload is already reporting why it is not running.
///
/// The companion usually goes down with the workload it supervises, so
/// without this the common case — a workload whose init exited, taking its
/// companion with it — reported "supervisor companion stopped unexpectedly"
/// and threw away the workload's own reason along with the console log that
/// came with it. A deliberate stop whose companion marker failed to write
/// went further and turned a recoverable `ContainerStopped` into a terminal
/// `ContainerExited`.
///
/// Transient reasons are not this: a sandbox that is merely starting, or
/// created and not yet started, is not explaining anything, so a companion in
/// trouble is still the most useful thing to report.
fn workload_explains_itself(status: &DriverSandboxStatus) -> bool {
    status.conditions.iter().any(|condition| {
        condition.r#type == "Ready"
            && condition.status == "False"
            && matches!(
                condition.reason.as_str(),
                CONDITION_EXITED | CONDITION_STOPPED | CONDITION_RUNTIME_RESTART | CONDITION_PAUSED
            )
    })
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
/// the placement's storage pool, a NIC on its network (behind `egress_acl`,
/// when given, with everything the ACL does not allow rejected both ways), a
/// read-only supervisor disk volume, a read-only DHCP client disk volume, and
/// an optional GPU device.
pub fn build_create_devices(
    placement: Placement<'_>,
    acls: &[&str],
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

    devices.insert("eth0".to_string(), sandbox_nic(placement.network, acls));

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

/// Where sandboxes land when their request names neither a network nor a
/// storage pool.
///
/// The operator can pin either with `--default-network` and
/// `--default-storage-pool`. What they do not pin is read off the project's
/// `default` profile, which is how an LXD project already says where its
/// instances go: point the driver at a project laid out for it and the
/// project's own answer is the one it uses.
///
/// The driver still names both devices explicitly on every instance it
/// creates rather than leaning on the profile to supply them, because it has
/// to attach the egress ACL to the NIC and place the supervisor and
/// DHCP-client volumes on the same pool as the rootfs. Resolving the defaults
/// from the profile keeps those explicit devices agreeing with the project
/// instead of overriding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementDefaults {
    pub network: String,
    pub storage_pool: String,
}

/// Name of the profile a project's placement defaults are read from.
pub const DEFAULT_PROFILE: &str = "default";

impl PlacementDefaults {
    /// Resolves the defaults from the operator's overrides and `profile`,
    /// LXD's `default` profile for the driver's project.
    ///
    /// Fails, rather than guessing a name, when neither source gives a value:
    /// a wrong guess creates sandboxes on the wrong network, which is the one
    /// mistake here that is not immediately visible.
    pub fn resolve(
        project: &str,
        profile: &lxd_client::Profile,
        network_override: Option<&str>,
        storage_pool_override: Option<&str>,
    ) -> Result<Self, DriverError> {
        let network = match network_override {
            Some(network) => network.to_string(),
            None => profile_device_value(profile, "nic", "network").ok_or_else(|| {
                DriverError::FailedPrecondition(format!(
                    "profile {:?} of project {project:?} has no NIC device naming a network;                      add one (lxc profile device add {} eth0 nic network=<network>                      --project {project}) or set the driver's --default-network",
                    profile.name, profile.name
                ))
            })?,
        };
        let storage_pool = match storage_pool_override {
            Some(pool) => pool.to_string(),
            None => profile_root_pool(profile).ok_or_else(|| {
                DriverError::FailedPrecondition(format!(
                    "profile {:?} of project {project:?} has no root disk device naming a                      storage pool; add one (lxc profile device add {} root disk path=/                      pool=<pool> --project {project}) or set the driver's                      --default-storage-pool",
                    profile.name, profile.name
                ))
            })?,
        };
        Ok(Self {
            network,
            storage_pool,
        })
    }
}

/// The `key` of the profile's device of type `device_type`, preferring the one
/// named `eth0` so a profile with several NICs resolves to the one LXD's own
/// conventions put first.
fn profile_device_value(
    profile: &lxd_client::Profile,
    device_type: &str,
    key: &str,
) -> Option<String> {
    let matching = |name: &str| {
        let device = profile.devices.get(name)?;
        (device.get("type").map(String::as_str) == Some(device_type))
            .then(|| device.get(key))
            .flatten()
            .filter(|value| !value.is_empty())
            .cloned()
    };
    matching("eth0").or_else(|| {
        let mut names: Vec<&String> = profile.devices.keys().collect();
        names.sort();
        names.into_iter().find_map(|name| matching(name))
    })
}

/// The pool of the profile's root disk, the device mounted at `/`.
fn profile_root_pool(profile: &lxd_client::Profile) -> Option<String> {
    let mut names: Vec<&String> = profile.devices.keys().collect();
    names.sort();
    names.into_iter().find_map(|name| {
        let device = profile.devices.get(name)?;
        if device.get("type").map(String::as_str) != Some("disk")
            || device.get("path").map(String::as_str) != Some("/")
        {
            return None;
        }
        device.get("pool").filter(|pool| !pool.is_empty()).cloned()
    })
}

impl<'a> Placement<'a> {
    /// The request's `driver_config.network` and `driver_config.storage_pool`,
    /// each falling back to the corresponding [`PlacementDefaults`] when
    /// unset, so users need not know how the LXD behind the gateway is laid
    /// out.
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
        let devices = build_create_devices(
            DEFAULTS,
            &[],
            false,
            "default",
            "vol1",
            "default",
            "dhcp-vol1",
        );

        assert!(!devices.contains_key("gpu0"));
        assert!(devices.contains_key("root"));
        assert!(devices.contains_key("eth0"));
        assert!(devices.contains_key("supervisor"));
        assert!(devices.contains_key("dhcp-client"));
    }

    #[test]
    fn build_create_devices_attaches_gpu_when_requested() {
        let devices = build_create_devices(
            DEFAULTS,
            &[],
            true,
            "default",
            "vol1",
            "default",
            "dhcp-vol1",
        );

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
            &[],
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

    /// A sandbox is two instances, so the name has to leave room for the
    /// second one. Validating against LXD's own 63 admitted a name whose
    /// companion LXD then refused — after the image was resolved, the volumes
    /// provisioned and the workload created, so what reached the caller was
    /// LXD complaining about a name it never typed.
    #[test]
    fn a_name_is_only_valid_if_its_companions_name_is_too() {
        let longest = "a".repeat(MAX_SANDBOX_NAME_LEN);
        assert!(is_valid_instance_name(&longest));
        assert_eq!(supervisor_instance_name(&longest).len(), 63);

        let one_too_long = "a".repeat(MAX_SANDBOX_NAME_LEN + 1);
        assert!(!is_valid_instance_name(&one_too_long));
        assert!(supervisor_instance_name(&one_too_long).len() > 63);
    }

    /// `foo-supervisor` is a name a user can give a sandbox, and then the
    /// instance called that is `foo-supervisor`'s *workload* — not `foo`'s
    /// companion. Every driver operation that reaches for a companion by
    /// name has to tell the two apart, or deleting `foo` destroys the other
    /// sandbox.
    #[test]
    fn a_sandbox_that_happens_to_hold_the_companion_name_is_not_a_companion() {
        let workload = instance_with(
            "Running",
            &[
                (KEY_SANDBOX_ID, "id-of-foo-supervisor"),
                (KEY_ROLE, ROLE_WORKLOAD),
            ],
        );
        assert!(!is_companion_of(&workload, "foo", None));

        // A real companion of a *different* sandbox is not this one's either.
        let other = instance_with(
            "Running",
            &[
                (KEY_SANDBOX_ID, "id-of-bar"),
                (KEY_ROLE, ROLE_SUPERVISOR),
                (KEY_WORKLOAD_INSTANCE, "bar"),
            ],
        );
        assert!(!is_companion_of(&other, "foo", None));

        // An unmanaged instance that merely has the name is not either.
        assert!(!is_companion_of(
            &instance_with("Running", &[]),
            "foo",
            None
        ));

        let mine = instance_with(
            "Running",
            &[
                (KEY_SANDBOX_ID, "id-of-foo"),
                (KEY_ROLE, ROLE_SUPERVISOR),
                (KEY_WORKLOAD_INSTANCE, "foo"),
            ],
        );
        assert!(is_companion_of(&mine, "foo", None));
        assert!(is_companion_of(&mine, "foo", Some("id-of-foo")));

        // Same name, same role, previous generation: a companion the last
        // sandbox called `foo` left behind is not this one's, however much
        // its name and role agree.
        assert!(!is_companion_of(&mine, "foo", Some("id-of-foo-the-second")));
    }

    /// The companion goes down with the workload it supervises, so this is
    /// the ordinary case, not an exotic one: without the guard every crashed
    /// sandbox reported its companion's exit instead of its own, and lost the
    /// console log that said why.
    #[test]
    fn a_companion_never_overwrites_a_workload_that_is_explaining_itself() {
        let companion_exited = instance_with(
            "Stopped",
            &[
                (KEY_SANDBOX_ID, "id"),
                (KEY_ROLE, ROLE_SUPERVISOR),
                (KEY_WORKLOAD_INSTANCE, "sb"),
                (KEY_LAST_POWER, "STOPPED"),
            ],
        );
        let companion_errored = instance_with(
            "Error",
            &[
                (KEY_SANDBOX_ID, "id"),
                (KEY_ROLE, ROLE_SUPERVISOR),
                (KEY_WORKLOAD_INSTANCE, "sb"),
            ],
        );

        for reason in [
            CONDITION_EXITED,
            CONDITION_STOPPED,
            CONDITION_RUNTIME_RESTART,
            CONDITION_PAUSED,
        ] {
            for companion in [&companion_exited, &companion_errored] {
                let mut sandbox = DriverSandbox {
                    status: Some(DriverSandboxStatus {
                        conditions: vec![DriverCondition {
                            r#type: "Ready".to_string(),
                            status: "False".to_string(),
                            reason: reason.to_string(),
                            message: "the workload's own message".to_string(),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                    ..Default::default()
                };

                aggregate_companion_status(&mut sandbox, Some(companion));

                let condition = &sandbox.status.expect("status").conditions[0];
                assert_eq!(condition.reason, reason);
                assert_eq!(condition.message, "the workload's own message");
            }
        }
    }

    /// ...but a workload that is not explaining anything still gets its
    /// companion's trouble reported, which is the only way it surfaces.
    #[test]
    fn a_companion_in_trouble_downgrades_a_workload_with_nothing_to_say() {
        let mut sandbox = DriverSandbox {
            status: Some(DriverSandboxStatus {
                conditions: vec![DriverCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        aggregate_companion_status(
            &mut sandbox,
            Some(&instance_with(
                "Stopped",
                &[
                    (KEY_SANDBOX_ID, "id"),
                    (KEY_ROLE, ROLE_SUPERVISOR),
                    (KEY_WORKLOAD_INSTANCE, "sb"),
                    (KEY_LAST_POWER, "STOPPED"),
                ],
            )),
        );

        let condition = &sandbox.status.expect("status").conditions[0];
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, CONDITION_EXITED);
        assert!(condition.message.contains("companion"), "{condition:?}");
    }

    /// A sandbox is only as ready as its trusted half, and the companion is
    /// hidden from every other query, so this is the only place its absence
    /// can be reported.
    #[test]
    fn a_missing_companion_makes_a_running_sandbox_not_ready() {
        let mut sandbox = DriverSandbox {
            status: Some(DriverSandboxStatus {
                conditions: vec![DriverCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        aggregate_companion_status(&mut sandbox, None);

        let conditions = sandbox.status.expect("status").conditions;
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0].status, "False");
        assert_eq!(conditions[0].reason, CONDITION_STARTING);
    }

    /// A workload that is already reporting why it is not running keeps
    /// saying so: replacing it would lose the reason the gateway needs.
    #[test]
    fn a_missing_companion_does_not_overwrite_a_workloads_own_reason() {
        let mut sandbox = DriverSandbox {
            status: Some(DriverSandboxStatus {
                conditions: vec![DriverCondition {
                    r#type: "Ready".to_string(),
                    status: "False".to_string(),
                    reason: CONDITION_EXITED.to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        aggregate_companion_status(&mut sandbox, None);

        assert_eq!(
            sandbox.status.expect("status").conditions[0].reason,
            CONDITION_EXITED
        );
    }

    /// A companion that is running says nothing the workload has not said.
    #[test]
    fn a_running_companion_leaves_the_sandbox_alone() {
        let mut sandbox = DriverSandbox {
            status: Some(DriverSandboxStatus {
                conditions: vec![DriverCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    reason: "ContainerRunning".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        aggregate_companion_status(&mut sandbox, Some(&instance_with("Running", &[])));

        let conditions = sandbox.status.expect("status").conditions;
        assert_eq!(conditions[0].status, "True");
        assert_eq!(conditions[0].reason, "ContainerRunning");
    }

    /// The init script boots two different binaries with two different
    /// argument sets and decides between them on this variable alone. A
    /// companion without it would try to start the workload boundary, which
    /// does not accept the arguments it has.
    #[test]
    fn only_the_companion_is_marked_as_the_supervisor_half() {
        let sandbox = identified_sandbox();
        let spec = DriverSandboxSpec::default();
        let template = DriverSandboxTemplate::default();

        let companion = build_supervisor_config(&sandbox, &spec, "", "info");
        assert_eq!(
            companion
                .get(&format!("environment.{ENV_ROLE}"))
                .map(String::as_str),
            Some(ROLE_SUPERVISOR)
        );
        assert_eq!(
            companion.get(KEY_ROLE).map(String::as_str),
            Some(ROLE_SUPERVISOR)
        );

        let workload = build_create_config(&sandbox, &spec, &template, 0, "info")
            .expect("build_create_config should succeed");
        assert!(!workload.contains_key(&format!("environment.{ENV_ROLE}")));
        assert_eq!(
            workload.get(KEY_ROLE).map(String::as_str),
            Some(ROLE_WORKLOAD)
        );
    }

    /// The SSH relay is the companion's; the workload never binds it.
    #[test]
    fn the_companion_gets_the_ssh_socket_path_and_the_workload_does_not() {
        let sandbox = DriverSandbox {
            id: "sb-123".to_string(),
            name: "test-sandbox".to_string(),
            ..Default::default()
        };
        let spec = DriverSandboxSpec::default();
        let template = DriverSandboxTemplate::default();

        let companion = build_supervisor_config(&sandbox, &spec, "", "info");
        assert_eq!(
            companion.get("environment.OPENSHELL_SSH_SOCKET_PATH"),
            Some(&GUEST_SSH_SOCKET_PATH.to_string())
        );

        let workload = build_create_config(&sandbox, &spec, &template, 0, "info")
            .expect("build_create_config should succeed");
        assert!(!workload.contains_key("environment.OPENSHELL_SSH_SOCKET_PATH"));
    }

    /// The condition for a sandbox found already stopped, which is what most
    /// of these tests are about; the live-event variant is covered on its own
    /// in [`a_live_stop_is_never_a_runtime_restart`].
    fn ready_condition_of(instance: &Instance) -> DriverCondition {
        ready_condition(instance, StopSeen::Discovered)
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
            expanded_devices: HashMap::new(),
            type_: "container".to_string(),
            project: "default".to_string(),
        }
    }

    /// Observed on LXD 6.9: an instance stopped by `snap restart lxd` and not
    /// autostarted keeps `volatile.last_state.power=RUNNING`; one whose init
    /// exited has `STOPPED`.
    #[test]
    fn stopped_by_the_runtime_is_a_runtime_restart() {
        let cond = ready_condition_of(&instance_with(
            "Stopped",
            &[("volatile.last_state.power", "RUNNING")],
        ));
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, CONDITION_RUNTIME_RESTART);

        // A requested stop wins: the driver stopped it, whatever LXD recorded.
        let requested = ready_condition_of(&instance_with(
            "Stopped",
            &[
                ("volatile.last_state.power", "RUNNING"),
                (KEY_STOP_INTENT, CONDITION_STOPPED),
            ],
        ));
        assert_eq!(requested.reason, CONDITION_STOPPED);
    }

    /// LXD rewrites `volatile.last_state.power` only once it has finished
    /// stopping an instance — 0.62–0.75s after the init exits, measured over
    /// 20 stops on LXD 6.9 — so the very state a dying sandbox passes through
    /// is the one a runtime restart is recognized by. A lifecycle event
    /// announcing the stop proves LXD is up, which settles it: the init
    /// exited.
    #[test]
    fn a_live_stop_is_never_a_runtime_restart() {
        let just_died = instance_with("Stopped", &[("volatile.last_state.power", "RUNNING")]);

        assert_eq!(
            ready_condition(&just_died, StopSeen::Live).reason,
            CONDITION_EXITED
        );
        assert_eq!(
            ready_condition(&just_died, StopSeen::Discovered).reason,
            CONDITION_RUNTIME_RESTART
        );
        let live = instance_to_driver_sandbox_live(&just_died)
            .status
            .expect("status is always reported");
        assert_eq!(live.conditions[0].reason, CONDITION_EXITED);

        // A stop that was asked for reads the same either way.
        let requested = instance_with(
            "Stopped",
            &[
                ("volatile.last_state.power", "RUNNING"),
                (KEY_STOP_INTENT, CONDITION_STOPPED),
            ],
        );
        assert_eq!(
            ready_condition(&requested, StopSeen::Live).reason,
            CONDITION_STOPPED
        );
    }

    /// The predicate the driver re-reads on must match the branch that
    /// reports the reason, or a sandbox would be waited for and then reported
    /// as something else.
    #[test]
    fn stopped_by_the_runtime_matches_the_reported_reason() {
        for (config, expected) in [
            (vec![("volatile.last_state.power", "RUNNING")], true),
            (vec![("volatile.last_state.power", "STOPPED")], false),
            (vec![], false),
            (
                vec![
                    ("volatile.last_state.power", "RUNNING"),
                    (KEY_STOP_INTENT, CONDITION_STOPPED),
                ],
                false,
            ),
        ] {
            let instance = instance_with("Stopped", &config);
            assert_eq!(stopped_by_the_runtime(&instance), expected, "{config:?}");
            assert_eq!(
                ready_condition_of(&instance).reason == CONDITION_RUNTIME_RESTART,
                expected,
                "{config:?}"
            );
        }

        // A running sandbox is never waiting to be confirmed.
        assert!(!stopped_by_the_runtime(&instance_with(
            "Running",
            &[("volatile.last_state.power", "RUNNING")]
        )));
    }

    /// The reason strings are a contract with the gateway, not cosmetic: it
    /// keys "is this transient?" and "may this be recovered at startup?" off
    /// these exact values.
    #[test]
    fn stopped_reason_distinguishes_death_from_requested_stop() {
        // Ran, then its init exited on its own → terminal ContainerExited.
        let died = instance_with("Stopped", &[("volatile.last_state.power", "STOPPED")]);
        let cond = ready_condition_of(&died);
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
        assert_eq!(ready_condition_of(&stopped).reason, CONDITION_STOPPED);
    }

    /// A created-but-never-started instance is also `Stopped` in LXD. Reporting
    /// it as `ContainerExited` would put a sandbox that is merely mid-create
    /// into a terminal, sticky `Error` at the gateway.
    #[test]
    fn never_started_instance_is_transient_not_terminal() {
        let fresh = instance_with("Stopped", &[]);
        let cond = ready_condition_of(&fresh);
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, CONDITION_CREATED);
    }

    #[test]
    fn running_and_guest_signalled_ready_are_both_ready() {
        assert_eq!(
            ready_condition_of(&instance_with("Running", &[])).status,
            "True"
        );
        // LXD reports `Ready` once a guest signals over devlxd; without this
        // arm it fell through to `Unknown`.
        assert_eq!(
            ready_condition_of(&instance_with("Ready", &[])).status,
            "True"
        );
    }

    #[test]
    fn transient_states_are_reported_with_transient_reasons() {
        assert_eq!(
            ready_condition_of(&instance_with("Starting", &[])).reason,
            CONDITION_STARTING
        );
        // An unrecognised status stays Unknown, which the gateway maps to
        // Provisioning rather than Error.
        assert_eq!(
            ready_condition_of(&instance_with("Weird", &[])).status,
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
        let cond = ready_condition_of(&instance_with("Frozen", &[]));
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
            let cond = ready_condition_of(&instance);
            assert!(
                !cond.message.is_empty(),
                "{} {:?} has no message",
                instance.status,
                instance.config
            );
        }
        assert_eq!(
            ready_condition_of(&instance_with("Running", &[])).message,
            ""
        );
    }

    #[test]
    fn exited_message_points_at_the_console_log() {
        let ran = ("volatile.last_state.power", "STOPPED");

        let cond = ready_condition_of(&instance_with("Stopped", &[ran]));
        assert!(
            cond.message.contains("`lxc console sb --show-log`"),
            "{}",
            cond.message
        );

        let in_project = Instance {
            project: "sandboxes".to_string(),
            ..instance_with("Stopped", &[ran])
        };
        let cond = ready_condition_of(&in_project);
        assert!(
            cond.message
                .contains("`lxc console sb --project sandboxes --show-log`"),
            "{}",
            cond.message
        );
    }

    #[test]
    fn lxd_error_status_is_reported_as_error() {
        let cond = ready_condition_of(&instance_with("Error", &[]));
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason, "Error");
    }

    /// Phase the OpenShell v0.0.116 gateway derives from a `Ready` condition
    /// (`crates/openshell-server/src/compute/mod.rs`, `derive_phase` and
    /// `is_terminal_failure_reason`, lines 4033-4131; the transient reasons
    /// are unchanged in v0.1.0-pre.1). Mirrored here so every reason the
    /// driver emits is checked against how the gateway reads it.
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
                instance_with("Stopped", &[("volatile.last_state.power", "RUNNING")]),
                "Error",
            ),
            (
                instance_with("Stopped", &[ran, (KEY_STOP_INTENT, CONDITION_STOPPED)]),
                "Error",
            ),
            (instance_with("Frozen", &[]), "Error"),
            (instance_with("Error", &[]), "Error"),
        ];

        for (instance, expected) in cases {
            let cond = ready_condition_of(&instance);
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
        assert_eq!(status.name, "sb-name");
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
            0,
            "info",
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
        // The boundary's namespaces, nftables fence and seccomp filter work
        // in an unnested container, so nesting is pinned off here and only
        // turned back on when `--sandbox-nesting` asks for it. Both keys are
        // pinned rather than left unset: unset means "whatever the profiles
        // say", and the project's `default` profile is one the driver does
        // not get to refuse.
        assert_eq!(
            config.get("security.nesting").map(String::as_str),
            Some("false"),
            "{config:?}"
        );
        assert_eq!(
            config.get("security.privileged").map(String::as_str),
            Some("false"),
            "{config:?}"
        );
        // This is the workload half, and it says so: every driver query
        // filters companions out by this key.
        assert_eq!(
            config.get(KEY_ROLE).map(String::as_str),
            Some(ROLE_WORKLOAD)
        );
        // The init script needs the id for the container's hostname. The
        // sandbox *name* is the companion's business.
        assert_eq!(
            config
                .get("environment.OPENSHELL_SANDBOX_ID")
                .map(String::as_str),
            Some("sb-123")
        );
        assert!(!config.contains_key("environment.OPENSHELL_SANDBOX"));
    }

    /// `StartSandboxRequest` has no template, so the only way a restart can
    /// run the workload as the account the policy named is for create to
    /// write it down.
    #[test]
    fn the_admitted_workload_selectors_are_recorded_for_a_restart() {
        let spec = DriverSandboxSpec {
            workload_identity: Some(computev1::pb::WorkloadIdentityRequest {
                user: " appuser ".to_string(),
                group: "appgroup".to_string(),
            }),
            ..Default::default()
        };
        let config = build_create_config(
            &identified_sandbox(),
            &spec,
            &DriverSandboxTemplate::default(),
            0,
            "info",
        )
        .expect("build_create_config should succeed");

        assert_eq!(
            config.get(KEY_WORKLOAD_USER).map(String::as_str),
            Some("appuser"),
            "the selector is recorded trimmed, as the resolver reads it"
        );
        assert_eq!(
            config.get(KEY_WORKLOAD_GROUP).map(String::as_str),
            Some("appgroup")
        );

        // Nothing requested records nothing: absent and empty mean the same
        // thing to the resolver, and an empty key would only be noise.
        let config = build_create_config(
            &identified_sandbox(),
            &DriverSandboxSpec::default(),
            &DriverSandboxTemplate::default(),
            0,
            "info",
        )
        .expect("build_create_config should succeed");
        assert!(!config.contains_key(KEY_WORKLOAD_USER));
        assert!(!config.contains_key(KEY_WORKLOAD_GROUP));
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

        let child_env = workload_child_env(&spec, &template);

        assert_eq!(
            child_env.get("SHARED").map(String::as_str),
            Some("from-template")
        );
        assert_eq!(child_env.get("SPEC_ONLY").map(String::as_str), Some("spec"));
        assert_eq!(
            child_env.get("TEMPLATE_ONLY").map(String::as_str),
            Some("template")
        );

        // ...and it stays out of the container's own environment, which is
        // the boundary's, not the workload's.
        let config = build_create_config(&identified_sandbox(), &spec, &template, 0, "info")
            .expect("build_create_config should succeed");
        assert!(!config.contains_key("environment.SHARED"));
        assert!(!config.contains_key("environment.SPEC_ONLY"));
    }

    /// The companion trusts these variables to know which sandbox it is and
    /// where to reach the gateway; request-supplied environment must not be
    /// able to redirect it. Under RFC 0012 that is structural rather than a
    /// matter of ordering: the request's environment is handed to the boundary
    /// for the workload's processes and never reaches either container's own.
    #[test]
    fn request_environment_cannot_redirect_either_half() {
        let hostile = env(&[
            ("OPENSHELL_SANDBOX_ID", "someone-else"),
            ("OPENSHELL_SANDBOX", "someone-else"),
            ("OPENSHELL_SSH_SOCKET_PATH", "/tmp/evil.sock"),
            ("OPENSHELL_ENDPOINT", "http://attacker:1"),
            (
                crate::isolation::ENV_ADMITTED_ISOLATION_BACKEND,
                "attacker-backend",
            ),
        ]);
        let spec = DriverSandboxSpec {
            environment: hostile.clone(),
            ..Default::default()
        };
        let template = DriverSandboxTemplate {
            environment: hostile,
            ..Default::default()
        };

        let companion = build_supervisor_config(
            &identified_sandbox(),
            &spec,
            "http://10.0.0.1:17670",
            "info",
        );
        let expected = [
            ("OPENSHELL_SANDBOX_ID", "sb-123"),
            ("OPENSHELL_SANDBOX", "test-sandbox"),
            ("OPENSHELL_SSH_SOCKET_PATH", GUEST_SSH_SOCKET_PATH),
            ("OPENSHELL_ENDPOINT", "http://10.0.0.1:17670"),
            (
                crate::isolation::ENV_ADMITTED_ISOLATION_BACKEND,
                crate::isolation::BACKEND_NAME,
            ),
        ];
        for (key, value) in expected {
            assert_eq!(
                companion
                    .get(&format!("environment.{key}"))
                    .map(String::as_str),
                Some(value),
                "{key}"
            );
        }

        let workload = build_create_config(&identified_sandbox(), &spec, &template, 0, "info")
            .expect("build_create_config should succeed");

        // The one the workload does get, and it is the driver's value.
        assert_eq!(
            workload
                .get("environment.OPENSHELL_SANDBOX_ID")
                .map(String::as_str),
            Some("sb-123")
        );
        // The rest are the companion's alone and must not appear at all.
        // Asserting they are merely not one particular hostile string would
        // miss the other four: `/tmp/evil.sock`, `http://attacker:1` and
        // `attacker-backend` would all have passed.
        for key in [
            "OPENSHELL_SANDBOX",
            "OPENSHELL_SSH_SOCKET_PATH",
            "OPENSHELL_ENDPOINT",
            crate::isolation::ENV_ADMITTED_ISOLATION_BACKEND,
        ] {
            assert!(
                !workload.contains_key(&format!("environment.{key}")),
                "{key} must not reach the workload at all"
            );
        }
        // And nothing the caller sent may appear under any OpenShell name.
        for (key, value) in &workload {
            if key.starts_with("environment.OPENSHELL_") {
                assert!(
                    ![
                        "someone-else",
                        "/tmp/evil.sock",
                        "http://attacker:1",
                        "attacker-backend"
                    ]
                    .contains(&value.as_str()),
                    "{key} carries a caller-supplied value: {value}"
                );
            }
        }
    }

    /// The main-process spec now travels on the companion, which is what runs
    /// it; the workload container never sees it.
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
            await_main_process_attachment: true,
            ..Default::default()
        };

        let config = build_supervisor_config(&identified_sandbox(), &spec, "", "info");

        assert_eq!(
            decoded_main_process(&config),
            serde_json::json!({
                "version": 1,
                "command": spec.command,
                "tty": false,
                "await_main_process_attachment": true,
            })
        );
    }

    /// Upstream's supervisor rejects an empty command, and falls back to an
    /// interactive login shell when no spec is given; match that.
    #[test]
    fn empty_command_is_the_default_login_shell() {
        // Nothing attaches to a shell nobody asked for, whatever the hint says.
        let spec = DriverSandboxSpec {
            await_main_process_attachment: true,
            ..Default::default()
        };
        let config = build_supervisor_config(&identified_sandbox(), &spec, "", "info");

        assert_eq!(
            decoded_main_process(&config),
            serde_json::json!({
                "version": 1,
                "command": ["/bin/bash", "-l"],
                "tty": true,
                "await_main_process_attachment": false,
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

        let config = build_supervisor_config(&identified_sandbox(), &spec, "", "info");

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

        let resolved = build_supervisor_config(
            &identified_sandbox(),
            &spec,
            "http://10.0.0.1:17670",
            "info",
        );
        assert_eq!(
            resolved
                .get("environment.OPENSHELL_ENDPOINT")
                .map(String::as_str),
            Some("http://10.0.0.1:17670")
        );

        // Empty means "not resolved", and leaves the companion without one.
        // The request's own environment is the workload's and never the
        // companion's, so it cannot stand in for a resolved endpoint.
        let unresolved = build_supervisor_config(&identified_sandbox(), &spec, "", "info");
        assert!(!unresolved.contains_key("environment.OPENSHELL_ENDPOINT"));
    }

    /// The sandbox JWT used to be staged as a file for the combined
    /// supervisor to read. Under RFC 0012 the gateway's launch authentication
    /// carries the credentials instead, and nothing about the token may reach
    /// instance config, which any LXD client with read access can see.
    #[test]
    fn the_sandbox_token_never_reaches_instance_config() {
        let spec = DriverSandboxSpec {
            sandbox_token: "eyJhbGciOiJFZERTQSJ9.secret-token".to_string(),
            ..Default::default()
        };
        let template = DriverSandboxTemplate::default();

        for config in [
            build_create_config(&identified_sandbox(), &spec, &template, 0, "info")
                .expect("build_create_config should succeed"),
            build_supervisor_config(&identified_sandbox(), &spec, "", "info"),
        ] {
            assert!(
                config.values().all(|v| !v.contains("secret-token")),
                "token leaked into instance config: {config:?}"
            );
            assert!(!config.contains_key("environment.OPENSHELL_SANDBOX_TOKEN"));
            assert!(!config.contains_key("environment.OPENSHELL_SANDBOX_TOKEN_FILE"));
        }
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
            0,
            "info",
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
            0,
            "info",
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
            0,
            "info",
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
            4096,
            "info",
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
                4096,
                "info",
            )
            .unwrap();
            assert_eq!(
                config.get("limits.processes").map(String::as_str),
                Some("4096")
            );
        }
    }

    #[test]
    fn guest_tls_environment_names_the_pushed_files() {
        let mut config = HashMap::new();
        insert_guest_tls_environment(&mut config);

        for (key, value) in [
            (
                "environment.OPENSHELL_TLS_CA",
                "/etc/openshell/tls/client/ca.crt",
            ),
            (
                "environment.OPENSHELL_TLS_CERT",
                "/etc/openshell/tls/client/tls.crt",
            ),
            (
                "environment.OPENSHELL_TLS_KEY",
                "/etc/openshell/tls/client/tls.key",
            ),
        ] {
            assert_eq!(config.get(key).map(String::as_str), Some(value), "{key}");
        }
    }

    fn profile(devices: &[(&str, &[(&str, &str)])]) -> lxd_client::Profile {
        let json = serde_json::json!({
            "name": "default",
            "devices": devices
                .iter()
                .map(|(name, props)| {
                    let props: HashMap<&str, &str> = props.iter().copied().collect();
                    ((*name).to_string(), props)
                })
                .collect::<HashMap<_, _>>(),
        });
        serde_json::from_value(json).expect("profile")
    }

    /// The MicroCloud layout: an OVN NIC and a root disk in the project's
    /// default profile, and nothing on the driver's command line.
    #[test]
    fn placement_defaults_from_profile() {
        let profile = profile(&[
            (
                "eth0",
                &[("type", "nic"), ("network", "default"), ("name", "eth0")],
            ),
            (
                "root",
                &[("type", "disk"), ("path", "/"), ("pool", "local")],
            ),
        ]);
        assert_eq!(
            PlacementDefaults::resolve("osh-mc", &profile, None, None).unwrap(),
            PlacementDefaults {
                network: "default".to_string(),
                storage_pool: "local".to_string(),
            }
        );
    }

    #[test]
    fn placement_defaults_prefer_flags_over_profile() {
        let profile = profile(&[
            ("eth0", &[("type", "nic"), ("network", "default")]),
            (
                "root",
                &[("type", "disk"), ("path", "/"), ("pool", "local")],
            ),
        ]);
        assert_eq!(
            PlacementDefaults::resolve("osh-mc", &profile, Some("ovn0"), None).unwrap(),
            PlacementDefaults {
                network: "ovn0".to_string(),
                storage_pool: "local".to_string(),
            }
        );
        assert_eq!(
            PlacementDefaults::resolve("osh-mc", &profile, None, Some("remote")).unwrap(),
            PlacementDefaults {
                network: "default".to_string(),
                storage_pool: "remote".to_string(),
            }
        );
    }

    /// A NIC not named `eth0` still answers, and `eth0` wins when both exist.
    #[test]
    fn placement_defaults_pick_a_nic() {
        let renamed = profile(&[
            ("enp5s0", &[("type", "nic"), ("network", "ovn0")]),
            (
                "root",
                &[("type", "disk"), ("path", "/"), ("pool", "local")],
            ),
        ]);
        assert_eq!(
            PlacementDefaults::resolve("osh-mc", &renamed, None, None)
                .unwrap()
                .network,
            "ovn0"
        );

        let both = profile(&[
            ("enp5s0", &[("type", "nic"), ("network", "ovn0")]),
            ("eth0", &[("type", "nic"), ("network", "default")]),
            (
                "root",
                &[("type", "disk"), ("path", "/"), ("pool", "local")],
            ),
        ]);
        assert_eq!(
            PlacementDefaults::resolve("osh-mc", &both, None, None)
                .unwrap()
                .network,
            "default"
        );
    }

    /// A disk that is not the rootfs does not place the rootfs.
    #[test]
    fn placement_defaults_ignore_non_root_disks() {
        let profile = profile(&[
            ("eth0", &[("type", "nic"), ("network", "default")]),
            (
                "scratch",
                &[("type", "disk"), ("path", "/scratch"), ("pool", "fast")],
            ),
        ]);
        let err = PlacementDefaults::resolve("osh-mc", &profile, None, None).unwrap_err();
        assert!(
            matches!(&err, DriverError::FailedPrecondition(m) if m.contains("root disk")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn placement_defaults_reject_a_profile_that_places_nothing() {
        let empty = profile(&[]);
        let err = PlacementDefaults::resolve("osh-mc", &empty, None, None).unwrap_err();
        assert!(
            matches!(&err, DriverError::FailedPrecondition(m) if m.contains("NIC device")),
            "unexpected error: {err}"
        );

        // Both pinned: an empty profile is then no obstacle.
        assert_eq!(
            PlacementDefaults::resolve("osh-mc", &empty, Some("ovn0"), Some("remote")).unwrap(),
            PlacementDefaults {
                network: "ovn0".to_string(),
                storage_pool: "remote".to_string(),
            }
        );
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

        let devices = build_create_devices(placement, &[], false, "fast", "sup", "fast", "dhcp");

        let root = devices.get("root").expect("root device");
        assert_eq!(root.get("pool").map(String::as_str), Some("fast"));
        assert_eq!(root.get("path").map(String::as_str), Some("/"));
        let eth0 = devices.get("eth0").expect("eth0 device");
        assert_eq!(eth0.get("type").map(String::as_str), Some("nic"));
        assert_eq!(eth0.get("network").map(String::as_str), Some("sandboxbr0"));
        assert!(!eth0.keys().any(|key| key.starts_with("security.acls")));
    }

    /// A sandbox's NIC carries two ACLs: the one its network shares, and the
    /// one that is its own. LXD takes them comma-separated, and the defaults
    /// stay `reject` in both directions whichever it is.
    #[test]
    fn a_nic_carries_both_acls_and_rejects_by_default() {
        let placement = Placement {
            network: "sandboxes",
            storage_pool: "local",
        };
        let devices = build_create_devices(
            placement,
            &["openshell-egress-sandboxes", "openshell-sbp-abc123"],
            false,
            "local",
            "sup",
            "local",
            "dhcp",
        );

        let eth0 = devices.get("eth0").expect("eth0 device");
        for (key, value) in [
            (
                "security.acls",
                "openshell-egress-sandboxes,openshell-sbp-abc123",
            ),
            ("security.acls.default.egress.action", "reject"),
            ("security.acls.default.ingress.action", "reject"),
        ] {
            assert_eq!(eth0.get(key).map(String::as_str), Some(value), "{key}");
        }

        // The companion sits behind the same pair: it is no more entitled to
        // the LAN than the workload it supervises.
        let devices = build_supervisor_devices(
            placement,
            &["openshell-egress-sandboxes", "openshell-sbp-abc123"],
            "local",
            "sup",
            "local",
            "dhcp",
        );
        assert_eq!(
            devices
                .get("eth0")
                .and_then(|nic| nic.get("security.acls"))
                .map(String::as_str),
            Some("openshell-egress-sandboxes,openshell-sbp-abc123")
        );
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

        let config = build_create_config(&sandbox, &spec, &template, 4096, "info")
            .expect("build_create_config should succeed");
        assert_eq!(config.get("limits.processes"), Some(&"4096".to_string()));

        // 0 means "leave pids.max alone".
        let unlimited = build_create_config(&sandbox, &spec, &template, 0, "info")
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
            4096,
            "info",
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
