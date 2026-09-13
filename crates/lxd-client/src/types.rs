// SPDX-License-Identifier: AGPL-3.0-or-later

//! Serde types mirroring LXD's REST API JSON shapes.

use std::collections::HashMap;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::LxdError;

/// LXD sends explicit JSON `null` (not a missing key) for several
/// `InstanceState` maps when an instance is stopped. `#[serde(default)]`
/// alone only handles a missing key, not an explicit `null`, so affected
/// fields also need this helper as their `deserialize_with`.
fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

/// Envelope every LXD REST API response is wrapped in.
///
/// `metadata` is the typed payload for `sync` responses, and for `async`
/// responses LXD inlines the full [`Operation`] there too (never just a bare
/// ID), so callers never need a follow-up `GET` to resolve it.
///
/// `status_code` is only meaningful for `sync`/`async` responses; LXD's own
/// error responses leave it `0` and report the real numeric code in
/// `error_code`.
#[derive(Debug, Clone, Deserialize)]
pub struct LxdResponse<T> {
    #[serde(rename = "type")]
    pub type_: String,
    pub status_code: u16,
    #[serde(default)]
    pub error_code: u16,
    pub metadata: Option<T>,
    pub error: Option<String>,
}

impl<T> LxdResponse<T> {
    /// Extracts `metadata`, or [`LxdError::Api`] if LXD reported success
    /// without a payload (unexpected, but checked rather than panicking).
    pub(crate) fn into_metadata(self) -> Result<T, LxdError> {
        self.metadata.ok_or_else(|| LxdError::Api {
            status_code: self.status_code,
            message: "LXD response missing metadata".to_string(),
        })
    }
}

/// A container or virtual machine, as returned by
/// `GET /1.0/instances/<name>` and `GET /1.0/instances?recursion=1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    /// Instance name (unique within a project).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Current lifecycle status string (e.g. `"Running"`, `"Stopped"`).
    pub status: String,
    /// Numeric LXD status code corresponding to `status`.
    pub status_code: u16,
    /// CPU architecture (e.g. `"x86_64"`).
    #[serde(default)]
    pub architecture: String,
    /// Whether the instance is ephemeral (deleted on stop).
    pub ephemeral: bool,
    /// LXD profiles applied to the instance, in order.
    pub profiles: Vec<String>,
    /// Raw LXD instance config keys (e.g. `limits.cpu`, `user.*`).
    pub config: HashMap<String, String>,
    /// Device configuration map (device name to key/value config).
    pub devices: HashMap<String, HashMap<String, String>>,
    /// Instance type: `"container"` or `"virtual-machine"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// LXD project the instance belongs to.
    pub project: String,
}

/// Runtime state of an instance, as returned by
/// `GET /1.0/instances/<name>/state`.
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceState {
    /// Current lifecycle status string (e.g. `"Running"`, `"Stopped"`).
    pub status: String,
    /// Numeric LXD status code corresponding to `status`.
    pub status_code: u16,
    /// Per-device disk usage. `null` rather than `{}` when the instance is stopped.
    #[serde(default, deserialize_with = "null_to_default")]
    pub disk: HashMap<String, InstanceStateDisk>,
    /// Memory usage summary.
    pub memory: InstanceStateMemory,
    /// Per-interface network state. `null` rather than `{}` when the instance is stopped.
    #[serde(default, deserialize_with = "null_to_default")]
    pub network: HashMap<String, InstanceStateNetwork>,
    /// PID of the instance's init process on the host, or `0` if stopped.
    pub pid: i64,
    /// Number of processes running inside the instance.
    pub processes: i64,
    /// CPU usage summary.
    pub cpu: InstanceStateCpu,
}

/// Disk usage for one device in [`InstanceState::disk`].
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceStateDisk {
    /// Bytes used on the device.
    pub usage: i64,
    /// Total capacity of the device in bytes, or `0` if unknown.
    #[serde(default)]
    pub total: i64,
}

/// Memory usage section of [`InstanceState`].
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceStateMemory {
    /// Current RSS memory usage in bytes.
    pub usage: i64,
    /// Peak RSS memory usage in bytes.
    #[serde(default)]
    pub usage_peak: i64,
    /// Total host memory available to the instance in bytes.
    #[serde(default)]
    pub total: i64,
    /// Current swap usage in bytes.
    #[serde(default)]
    pub swap_usage: i64,
    /// Peak swap usage in bytes.
    #[serde(default)]
    pub swap_usage_peak: i64,
}

/// CPU usage section of [`InstanceState`].
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceStateCpu {
    /// Cumulative CPU time used by the instance in nanoseconds.
    pub usage: i64,
}

/// Network interface state for one device in [`InstanceState::network`].
///
/// IP addresses live in [`InstanceStateNetworkAddress::address`], nested
/// under `addresses`, not as a flat field on this struct.
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceStateNetwork {
    /// IP addresses assigned to this interface.
    #[serde(default)]
    pub addresses: Vec<InstanceStateNetworkAddress>,
    /// MAC address of the interface.
    #[serde(default)]
    pub hwaddr: String,
    /// Host-side veth interface name.
    #[serde(default)]
    pub host_name: String,
    /// MTU of the interface in bytes.
    #[serde(default)]
    pub mtu: i64,
    /// Interface state: `"up"` or `"down"`.
    #[serde(default)]
    pub state: String,
    /// Interface type (e.g. `"broadcast"`, `"loopback"`).
    #[serde(rename = "type", default)]
    pub type_: String,
}

/// A single address entry within [`InstanceStateNetwork::addresses`].
#[derive(Debug, Clone, Deserialize)]
pub struct InstanceStateNetworkAddress {
    /// Address family: `"inet"` (IPv4) or `"inet6"` (IPv6).
    pub family: String,
    /// The IP address as a string (e.g. `"10.0.0.5"`).
    pub address: String,
    /// Prefix length as a string (e.g. `"24"`).
    #[serde(default)]
    pub netmask: String,
    /// Address scope: `"global"`, `"link"`, or `"local"`.
    #[serde(default)]
    pub scope: String,
}

/// An asynchronous background operation, returned by every mutating
/// instance endpoint and by `GET /1.0/operations/<id>/wait`.
#[derive(Debug, Clone, Deserialize)]
pub struct Operation {
    /// Bare UUID of the operation (without the `/1.0/operations/` prefix).
    pub id: String,
    /// Operation class: `"task"`, `"websocket"`, or `"token"`.
    #[serde(default)]
    pub class: String,
    /// Human-readable description (e.g. `"Creating container"`).
    #[serde(default)]
    pub description: String,
    /// Terminal status: `Success`, `Failure`, or intermediate `Running`.
    pub status: OperationStatus,
    /// Numeric LXD status code corresponding to `status`.
    pub status_code: u16,
    /// Resources affected by the operation (e.g. `{"instances": ["/1.0/instances/foo"]}`).
    #[serde(default)]
    pub resources: HashMap<String, Vec<String>>,
    /// Error message if the operation failed; empty string on success.
    #[serde(default)]
    pub err: String,
    /// Cluster member the operation is running on.
    #[serde(default)]
    pub location: String,
    /// Additional metadata returned by the operation upon completion (e.g. image fingerprint).
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Lifecycle status of an [`Operation`], as reported by LXD's `status`
/// field (also mirrored in the `status` key of
/// `/1.0/events?type=operation` frames).
///
/// LXD reports several transient statuses beyond the ones any caller in
/// this crate inspects (`Starting`, `Stopping`, `Aborting`, ...); any
/// value that isn't one of the terminal/pending statuses handled here is
/// always non-terminal, so [`OperationStatus::Other`] captures those
/// without needing this enum to track LXD's full status list.
#[derive(Clone, Debug, Eq, PartialEq, strum::Display, strum::EnumString)]
pub enum OperationStatus {
    Pending,
    Running,
    Success,
    Failure,
    Cancelled,
    #[strum(default)]
    Other(String),
}

impl<'de> Deserialize<'de> for OperationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// Server info, as returned by `GET /1.0`.
#[derive(Debug, Clone, Deserialize)]
pub struct LxdServerInfo {
    /// List of API extension names supported by this LXD server.
    #[serde(default)]
    pub api_extensions: Vec<String>,
}

/// A single event frame from `GET /1.0/events`.
#[derive(Debug, Clone, Deserialize)]
pub struct LxdEvent {
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,
    /// Event type: `"operation"`, `"lifecycle"`, `"logging"`, etc.
    #[serde(rename = "type")]
    pub type_: String,
    /// Raw event payload; shape varies by `type_`.
    pub metadata: serde_json::Value,
}

/// A managed network, as returned by `GET /1.0/networks/<name>`.
///
/// `config` keys of interest: `ipv4.address` / `ipv6.address` hold the
/// bridge's own host-side address in CIDR form (e.g. `"10.0.0.1/24"`).
#[derive(Debug, Clone, Deserialize)]
pub struct Network {
    /// Network name (e.g. `"lxdbr0"`).
    pub name: String,
    /// Network type (e.g. `"bridge"`, `"physical"`).
    #[serde(rename = "type")]
    pub type_: String,
    /// Network configuration key/value pairs.
    #[serde(default)]
    pub config: HashMap<String, String>,
}

/// An image as listed by `GET /1.0/images?recursion=1`.
#[derive(Debug, Clone, Deserialize)]
pub struct Image {
    /// Full SHA-256 fingerprint.
    pub fingerprint: String,
    /// Project the image belongs to. A project without its own images lists
    /// the `default` project's.
    #[serde(default)]
    pub project: String,
    /// Aliases pointing at the image.
    #[serde(default)]
    pub aliases: Vec<ImageAlias>,
}

/// One alias of an [`Image`].
#[derive(Debug, Clone, Deserialize)]
pub struct ImageAlias {
    pub name: String,
}

/// A storage volume as listed by
/// `GET /1.0/storage-pools/<pool>/volumes/<type>?recursion=1`.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageVolume {
    pub name: String,
    /// Project the volume belongs to. A project without its own storage
    /// volumes lists the `default` project's.
    #[serde(default)]
    pub project: String,
    /// API paths of what uses the volume, e.g. the instances it is attached to.
    #[serde(default)]
    pub used_by: Vec<String>,
    /// Cluster member holding the volume, for pools local to each member;
    /// empty otherwise.
    #[serde(default)]
    pub location: String,
}
