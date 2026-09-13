// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network ACL management.

use serde_json::json;

use crate::client::LxdClient;
use crate::error::LxdError;
use crate::types::Operation;

/// A single LXD Network ACL rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LxdNetworkAclRule {
    /// Rule action.
    pub action: AclAction,
    /// Comma-separated destination CIDRs, ranges or addresses
    /// (e.g. `"10.0.0.0/8"`); empty matches any destination.
    pub destination: String,
    /// Destination port or range (e.g. `"8080"`, `"8080-8090"`); empty
    /// matches any port. Needs a TCP or UDP `protocol`.
    pub destination_port: String,
    /// IP protocol; `None` matches any.
    pub protocol: Option<AclProtocol>,
    /// Free-form description shown by `lxc network acl show`.
    pub description: String,
    /// Rule state.
    pub state: AclState,
}

impl LxdNetworkAclRule {
    /// Allow egress TCP to a specific destination CIDR and port.
    pub fn allow_egress_tcp(dest_cidr: &str, dest_port: u16) -> Self {
        Self::allow_egress(dest_cidr, Some(AclProtocol::Tcp), &dest_port.to_string())
    }

    /// Allow egress to `destination`, optionally only for one protocol and
    /// port (an empty `destination_port` matches any).
    pub fn allow_egress(
        destination: &str,
        protocol: Option<AclProtocol>,
        destination_port: &str,
    ) -> Self {
        Self {
            action: AclAction::Allow,
            destination: destination.to_string(),
            destination_port: destination_port.to_string(),
            protocol,
            description: String::new(),
            state: AclState::Enabled,
        }
    }

    /// Sets the rule's description.
    #[must_use]
    pub fn described(mut self, description: &str) -> Self {
        self.description = description.to_string();
        self
    }

    /// The rule as LXD's API returns it: fields that are unset are left out
    /// rather than sent empty, so a rule read back compares equal.
    fn to_json(&self) -> serde_json::Value {
        let protocol = self.protocol.map(|p| p.to_string()).unwrap_or_default();
        let mut rule = serde_json::Map::new();
        for (key, value) in [
            ("action", self.action.to_string()),
            ("description", self.description.clone()),
            ("destination", self.destination.clone()),
            ("destination_port", self.destination_port.clone()),
            ("protocol", protocol),
            ("state", self.state.to_string()),
        ] {
            if !value.is_empty() {
                rule.insert(key.to_string(), serde_json::Value::String(value));
            }
        }
        serde_json::Value::Object(rule)
    }
}

/// [`LxdNetworkAclRule::action`]: whether matching traffic is allowed or dropped.
#[derive(Copy, Clone, Debug, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum AclAction {
    Allow,
    Drop,
    Reject,
}

/// [`LxdNetworkAclRule::protocol`]: the IP protocol a rule matches on.
#[derive(Copy, Clone, Debug, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum AclProtocol {
    Tcp,
    Udp,
    Icmp,
}

/// [`LxdNetworkAclRule::state`]: whether a rule is enforced.
#[derive(Copy, Clone, Debug, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum AclState {
    Enabled,
    Disabled,
}

impl LxdClient {
    /// Ensures a named Network ACL exists with exactly the given egress rules
    /// and no ingress rules.
    ///
    /// Creates the ACL if it does not exist (`POST /1.0/network-acls`), leaves
    /// it alone if it already has these rules, and otherwise replaces its
    /// rules (`PUT /1.0/network-acls/<name>`). The writes run as background
    /// operations, so this waits on them before returning; otherwise a
    /// caller that reads the ACL back immediately (or a subsequent call to
    /// this method) could race the operation and see stale state. Idempotent.
    pub async fn ensure_network_acl(
        &self,
        name: &str,
        egress: Vec<LxdNetworkAclRule>,
    ) -> Result<(), LxdError> {
        let egress_json: Vec<serde_json::Value> =
            egress.iter().map(LxdNetworkAclRule::to_json).collect();

        // LXD's PUT payload (NetworkACLPut) is the writable-fields-only shape;
        // unlike POST (NetworkACLsPost) it must not carry `name`, or LXD's
        // uniqueness validation on that field rejects the update as a
        // collision with the (identically-named) ACL it's replacing.
        let update_body = json!({
            "description": "OpenShell sandbox egress policy",
            "egress": egress_json,
            "ingress": [],
            "config": {},
        });
        let create_body = {
            let mut body = update_body.clone();
            body["name"] = json!(name);
            body
        };

        match self
            .get::<serde_json::Value>(&format!("/1.0/network-acls/{name}"))
            .await
        {
            Ok(response) => {
                let current = response.into_metadata()?;
                if acl_matches(&current, &update_body) {
                    return Ok(());
                }
                let op = self
                    .put::<Operation>(&format!("/1.0/network-acls/{name}"), update_body)
                    .await?
                    .into_metadata()?;
                self.wait_operation(&op.id).await?;
            }
            Err(LxdError::Api {
                status_code: 404, ..
            }) => {
                match self
                    .post::<Operation>("/1.0/network-acls", create_body)
                    .await
                {
                    Ok(resp) => {
                        let op = resp.into_metadata()?;
                        self.wait_operation(&op.id).await?;
                    }
                    // A concurrent caller created the ACL between our GET and POST.
                    Err(LxdError::Api {
                        status_code: 409, ..
                    }) => {
                        let op = self
                            .put::<Operation>(&format!("/1.0/network-acls/{name}"), update_body)
                            .await?
                            .into_metadata()?;
                        self.wait_operation(&op.id).await?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Deletes a named Network ACL. A 404 response is treated as success.
    /// `DELETE /1.0/network-acls/<name>` runs as a background operation, so
    /// this waits on it before returning.
    pub async fn delete_network_acl(&self, name: &str) -> Result<(), LxdError> {
        match self
            .delete::<Operation>(&format!("/1.0/network-acls/{name}"))
            .await
        {
            Ok(resp) => {
                let op = resp.into_metadata()?;
                self.wait_operation(&op.id).await?;
                Ok(())
            }
            Err(LxdError::Api {
                status_code: 404, ..
            }) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Whether an ACL as LXD returns it already has the rules in `desired`.
fn acl_matches(current: &serde_json::Value, desired: &serde_json::Value) -> bool {
    let rules = |acl: &serde_json::Value, key: &str| -> Vec<serde_json::Value> {
        acl.get(key)
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    current.get("description") == desired.get("description")
        && rules(current, "egress") == rules(desired, "egress")
        && rules(current, "ingress") == rules(desired, "ingress")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape observed from `GET /1.0/network-acls/<name>` on LXD 6.9.
    #[test]
    fn rules_serialize_as_lxd_returns_them() {
        let rule =
            LxdNetworkAclRule::allow_egress("192.0.2.0/24", None, "").described("public ipv4");
        assert_eq!(
            rule.to_json(),
            json!({
                "action": "allow",
                "destination": "192.0.2.0/24",
                "description": "public ipv4",
                "state": "enabled",
            })
        );
        assert_eq!(
            LxdNetworkAclRule::allow_egress_tcp("10.0.0.1", 53).to_json()["protocol"],
            "tcp"
        );
    }

    #[test]
    fn matching_ignores_fields_it_does_not_manage() {
        let desired = json!({
            "description": "OpenShell sandbox egress policy",
            "egress": [LxdNetworkAclRule::allow_egress_tcp("10.0.0.1", 53).to_json()],
            "ingress": [],
            "config": {},
        });
        let mut current = desired.clone();
        current["name"] = json!("acl");
        current["used_by"] = json!(["/1.0/instances/sb"]);
        current["project"] = json!("openshell");
        assert!(acl_matches(&current, &desired));

        current["egress"][0]["destination"] = json!("10.0.0.2");
        assert!(!acl_matches(&current, &desired));
    }
}
