// SPDX-License-Identifier: AGPL-3.0-or-later

//! The operator-owned resource admission policy, mirrored from the gateway.
//!
//! From OpenShell v0.1.0-pre.5 a gateway refuses to provision through a driver
//! whose `GetCapabilities` does not echo the admission policy the *gateway* was
//! configured with, byte for byte: it compares its own
//! `DriverAdmissionConfig::acknowledgement()` with the driver's
//! `resource_admission_policy`, and fails `CreateSandbox`, `StartSandbox` and
//! `ValidateSandboxCreate` with `failed_precondition` when they differ. There
//! is no negotiation and no partial match, so the types below reproduce
//! upstream's serialization exactly — field order, defaults and the `v1:`
//! prefix — rather than approximating it.
//!
//! The policy has two halves. `allow_driver_config` gates caller-supplied
//! `template.driver_config`, which this driver reads for `network`,
//! `storage_pool`, `max_processes` and `profiles`; the driver enforces it
//! itself as well, because a gateway is not the only thing that can call a
//! driver socket. `resource_admission` gates *external* resources a sandbox
//! attaches by label, which on LXD is nothing today: sandboxes get a root disk
//! and a NIC from the project's profile, and a GPU request attaches host GPUs,
//! which upstream exempts. It is still acknowledged, because the gateway
//! compares the whole policy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Label value upstream substitutes with the sandbox's workspace.
const WORKSPACE_PLACEHOLDER: &str = "${workspace}";

/// Label keys upstream reserves for driver-owned metadata.
const RESERVED_LABEL_KEYS: [&str; 3] = [
    "openshell.ai/managed-by",
    "openshell.ai/gateway-id",
    "openshell.ai/sandbox-workspace",
];

/// Effective policy acknowledged by the driver.
///
/// Mirrors `openshell_core::resource_admission::DriverAdmissionConfig`. The
/// field order below is the JSON field order, and changing it changes the
/// acknowledgement string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DriverAdmissionConfig {
    pub allow_driver_config: bool,
    pub resource_admission: ResourceAdmissionConfig,
}

/// Label policy for external resources a sandbox may attach.
///
/// Mirrors `openshell_core::resource_admission::ResourceAdmissionConfig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceAdmissionConfig {
    pub enabled: bool,
    pub required_labels: BTreeMap<String, String>,
}

impl Default for ResourceAdmissionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required_labels: BTreeMap::from([
                (
                    "openshell.ai/sandbox-attachable".to_string(),
                    "true".to_string(),
                ),
                (
                    "openshell.ai/sandbox-attachable-workspace".to_string(),
                    WORKSPACE_PLACEHOLDER.to_string(),
                ),
            ]),
        }
    }
}

impl DriverAdmissionConfig {
    /// The versioned acknowledgement the gateway compares against its own.
    ///
    /// Upstream builds this with `serde_json::to_string`, which emits struct
    /// fields in declaration order and `BTreeMap` keys in sorted order, so the
    /// string is stable for a given policy.
    #[must_use]
    pub fn acknowledgement(&self) -> String {
        // Only strings, booleans and string-keyed maps: serialization cannot
        // fail.
        format!(
            "v1:{}",
            serde_json::to_string(self).expect("serializable admission policy")
        )
    }

    /// Rejects a policy the gateway would reject too, at startup rather than
    /// on the first sandbox.
    pub fn validate(&self) -> Result<(), String> {
        self.resource_admission.validate()
    }
}

impl ResourceAdmissionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.required_labels.is_empty() {
            return Err("resource admission is enabled with no required labels".to_string());
        }
        for key in self.required_labels.keys() {
            if RESERVED_LABEL_KEYS.contains(&key.as_str()) {
                return Err(format!(
                    "resource admission label key is reserved for driver-owned metadata: {key}"
                ));
            }
        }
        if self
            .required_labels
            .values()
            .all(|value| value == WORKSPACE_PLACEHOLDER)
        {
            return Err(
                "resource admission required labels must include a shared approval label"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The acknowledgement a stock gateway computes for a driver it was given
    /// no `[openshell.drivers.lxd]` configuration for. Taken from upstream's
    /// own defaults; if this test fails against a new release, the driver and
    /// every gateway it talks to have drifted apart and sandboxes will be
    /// refused with `failed_precondition`.
    #[test]
    fn default_acknowledgement_matches_the_gateway_default() {
        assert_eq!(
            DriverAdmissionConfig::default().acknowledgement(),
            concat!(
                r#"v1:{"allow_driver_config":false,"resource_admission":{"enabled":true,"#,
                r#""required_labels":{"openshell.ai/sandbox-attachable":"true","#,
                r#""openshell.ai/sandbox-attachable-workspace":"${workspace}"}}}"#,
            )
        );
    }

    #[test]
    fn allowing_driver_config_changes_the_acknowledgement() {
        let policy = DriverAdmissionConfig {
            allow_driver_config: true,
            ..DriverAdmissionConfig::default()
        };
        assert!(policy
            .acknowledgement()
            .contains(r#""allow_driver_config":true"#));
        assert_ne!(
            policy.acknowledgement(),
            DriverAdmissionConfig::default().acknowledgement()
        );
    }

    /// An explicit opt-out is a legal policy: upstream accepts a driver that
    /// reports one as long as the gateway is configured the same way.
    #[test]
    fn disabled_admission_needs_no_labels() {
        let policy = DriverAdmissionConfig {
            allow_driver_config: false,
            resource_admission: ResourceAdmissionConfig {
                enabled: false,
                required_labels: BTreeMap::new(),
            },
        };
        policy.validate().expect("opt-out is a valid policy");
        assert_eq!(
            policy.acknowledgement(),
            r#"v1:{"allow_driver_config":false,"resource_admission":{"enabled":false,"required_labels":{}}}"#
        );
    }

    #[test]
    fn enabled_admission_rejects_an_empty_label_set() {
        let policy = DriverAdmissionConfig {
            allow_driver_config: false,
            resource_admission: ResourceAdmissionConfig {
                enabled: true,
                required_labels: BTreeMap::new(),
            },
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn enabled_admission_rejects_workspace_only_labels() {
        let policy = DriverAdmissionConfig {
            allow_driver_config: false,
            resource_admission: ResourceAdmissionConfig {
                enabled: true,
                required_labels: BTreeMap::from([(
                    "example.com/workspace".to_string(),
                    WORKSPACE_PLACEHOLDER.to_string(),
                )]),
            },
        };
        assert!(policy.validate().is_err());
    }
}
