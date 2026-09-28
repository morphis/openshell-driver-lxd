// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network ACL management.

use serde_json::json;
use urlencoding::encode;

use crate::client::LxdClient;
use crate::error::LxdError;
use crate::types::Operation;

/// A single LXD Network ACL rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LxdNetworkAclRule {
    /// Rule action.
    pub action: AclAction,
    /// Comma-separated source CIDRs, ranges or addresses; empty matches any
    /// source. Only meaningful on an ingress rule.
    pub source: String,
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
            source: String::new(),
            destination: destination.to_string(),
            destination_port: destination_port.to_string(),
            protocol,
            description: String::new(),
            state: AclState::Enabled,
        }
    }

    /// Allow ingress from `source` to a TCP port.
    ///
    /// LXD applies ingress rules to traffic entering the NIC, so `source` is
    /// where it came from and `destination_port` is the port it is headed for.
    pub fn allow_ingress_tcp(source: &str, destination_port: u16) -> Self {
        Self {
            action: AclAction::Allow,
            source: source.to_string(),
            destination: String::new(),
            destination_port: destination_port.to_string(),
            protocol: Some(AclProtocol::Tcp),
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
            ("source", self.source.clone()),
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
    /// Ensures a named Network ACL exists with exactly the given rules.
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
        ingress: Vec<LxdNetworkAclRule>,
    ) -> Result<(), LxdError> {
        let egress_json: Vec<serde_json::Value> =
            egress.iter().map(LxdNetworkAclRule::to_json).collect();
        let ingress_json: Vec<serde_json::Value> =
            ingress.iter().map(LxdNetworkAclRule::to_json).collect();

        // LXD's PUT payload (NetworkACLPut) is the writable-fields-only shape;
        // unlike POST (NetworkACLsPost) it must not carry `name`, or LXD's
        // uniqueness validation on that field rejects the update as a
        // collision with the (identically-named) ACL it's replacing.
        let update_body = json!({
            "description": DESCRIPTION,
            "egress": egress_json,
            "ingress": ingress_json,
            "config": {},
        });
        // Created empty, then filled by the update below. A rule may name the
        // ACL it belongs to as a subject selector — which is how a driver
        // says "this sandbox's own NICs" without knowing their addresses —
        // and LXD validates subjects against the ACLs that exist when the
        // rule is written. Sending the rules with the POST would have LXD
        // reject a self-reference to an ACL it has not created yet.
        let create_body = json!({
            "name": name,
            "description": DESCRIPTION,
            "egress": [],
            "ingress": [],
            "config": {},
        });

        match self
            .get::<serde_json::Value>(&format!("/1.0/network-acls/{}", encode(name)))
            .await
        {
            Ok(response) => {
                let current = response.into_metadata()?;
                if acl_matches(&current, &update_body) {
                    return Ok(());
                }
                // Somebody else's ACL of the same name is not this driver's to
                // rewrite. The description is the only marker LXD keeps that
                // says whose it is, so an ACL carrying a different one is
                // refused rather than adopted — which is what the driver would
                // otherwise do, silently replacing an operator's rules with
                // its own.
                if current
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description != DESCRIPTION)
                {
                    return Err(LxdError::Api {
                        status_code: 409,
                        message: format!(
                            "network ACL {name:?} already exists and is not managed by this \
                             driver; remove it or choose another network"
                        ),
                    });
                }
                let op = self
                    .put::<Operation>(&format!("/1.0/network-acls/{}", encode(name)), update_body)
                    .await?
                    .into_metadata()?;
                self.wait_operation(&op.id).await?;
            }
            Err(LxdError::Api {
                status_code: 404, ..
            }) => {
                // A concurrent caller can create the ACL between this GET and
                // the POST below, and LXD reports that two ways: it rejects
                // the request with a 409, or it accepts it and fails the
                // operation with a uniqueness violation once it reaches the
                // database. Both mean the ACL now exists, so both fall through
                // to the same update — a driver ensures its ACL on every
                // sandbox create, and two creates at once are ordinary.
                let created = async {
                    let op = self
                        .post::<Operation>("/1.0/network-acls", create_body)
                        .await?
                        .into_metadata()?;
                    self.wait_operation(&op.id).await
                }
                .await;
                if let Err(e) = created {
                    if !is_already_created(&e) {
                        return Err(e);
                    }
                }
                // Either way the ACL now exists and is empty or stale, so the
                // rules go in with an update.
                let op = self
                    .put::<Operation>(&format!("/1.0/network-acls/{}", encode(name)), update_body)
                    .await?
                    .into_metadata()?;
                self.wait_operation(&op.id).await?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Lists the project's Network ACLs with the instances and profiles using
    /// each, as `(name, used_by)`.
    ///
    /// `used_by` empty means nothing references the ACL, which is how
    /// clean-up recognizes one whose sandbox is gone.
    pub async fn list_network_acls(&self) -> Result<Vec<(String, Vec<String>)>, LxdError> {
        #[derive(serde::Deserialize)]
        struct Acl {
            name: String,
            #[serde(default)]
            used_by: Vec<String>,
        }

        let acls: Vec<Acl> = self
            .get::<Vec<Acl>>("/1.0/network-acls?recursion=1")
            .await?
            .into_metadata()?;
        Ok(acls
            .into_iter()
            .map(|acl| (acl.name, acl.used_by))
            .collect())
    }

    /// Deletes a named Network ACL. A 404 response is treated as success.
    /// `DELETE /1.0/network-acls/<name>` runs as a background operation, so
    /// this waits on it before returning.
    pub async fn delete_network_acl(&self, name: &str) -> Result<(), LxdError> {
        match self
            .delete::<Operation>(&format!("/1.0/network-acls/{}", encode(name)))
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

/// Description stamped on every ACL the driver manages, and compared on
/// update so an operator's own ACL of the same name is not silently adopted.
const DESCRIPTION: &str = "OpenShell sandbox egress policy";

/// Whether `error` says the ACL this call tried to create already exists.
///
/// LXD reports a duplicate three ways, and a driver that ensures its ACLs on
/// every sandbox create meets all of them:
///
/// - synchronously with its own sentence, which LXD 6.9 returns under **400**
///   rather than the 409 the status alone would suggest — matching the status
///   is what made concurrent creates fail with "The network ACL already
///   exists" surfaced to the caller as an invalid argument;
/// - synchronously with 409, from versions that notice earlier in the handler;
/// - asynchronously with its database's uniqueness error, when it does not
///   notice until the operation reaches SQLite.
///
/// The sentence is matched rather than the status because the status has
/// already changed once, and a duplicate is the one thing this call is
/// entitled to ignore: it goes on to update the ACL it found.
fn is_already_created(error: &LxdError) -> bool {
    match error {
        LxdError::Api {
            status_code,
            message,
        } => *status_code == 409 || message.contains("already exists"),
        LxdError::OperationFailed { err, .. } => {
            err.contains("UNIQUE constraint failed: networks_acls")
        }
        _ => false,
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

    /// LXD 6.9 reports a duplicate ACL two ways depending on where it
    /// notices, and a driver that ensures its ACL on every sandbox create
    /// meets both. Recorded verbatim, so a change in wording fails here
    /// rather than turning concurrent creates back into failures.
    #[test]
    fn a_concurrently_created_acl_is_recognized_however_lxd_reports_it() {
        // LXD 6.9, verified against a live daemon: a duplicate create comes
        // back under 400, not 409. Keying on the status alone let two
        // concurrent sandbox creates fail with this sentence surfaced to the
        // caller as an invalid argument.
        assert!(is_already_created(&LxdError::Api {
            status_code: 400,
            message: "The network ACL already exists".to_string(),
        }));
        assert!(is_already_created(&LxdError::Api {
            status_code: 409,
            message: "The network ACL already exists".to_string(),
        }));
        assert!(is_already_created(&LxdError::OperationFailed {
            description: "Creating network ACL".to_string(),
            err: "UNIQUE constraint failed: networks_acls.project_id, networks_acls.name"
                .to_string(),
        }));

        // Anything else is a real failure and must not be swallowed.
        for other in [
            LxdError::Api {
                status_code: 403,
                message: "not authorized".to_string(),
            },
            LxdError::OperationFailed {
                description: "Creating network ACL".to_string(),
                err: "Invalid rule: unknown action".to_string(),
            },
        ] {
            assert!(!is_already_created(&other), "{other:?}");
        }
    }

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
