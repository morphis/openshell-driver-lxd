// SPDX-License-Identifier: AGPL-3.0-or-later

//! LXD lifecycle event watcher.
//!
//! Without this, the gateway only learns that a sandbox died on its next
//! polling reconcile — up to a minute later. LXD publishes a lifecycle event
//! the moment an instance's init exits, so the driver subscribes to that
//! stream and pushes an updated sandbox snapshot straight away, the same way
//! the upstream Podman driver forwards runtime events.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use lxd_client::{LxdClient, LxdEvent};
use tokio::sync::broadcast;

use crate::grpc::WatchEvent;
use crate::mapping;

/// How long to wait before re-subscribing after the event stream ends or
/// errors. LXD restarts (snap refreshes) drop the stream; reconnecting keeps
/// the driver reporting promptly afterwards without spinning on a daemon that
/// is still coming back up.
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(2);

/// Lifecycle actions worth re-reading an instance for.
///
/// `instance-shutdown` is the interesting one: LXD emits it when the guest's
/// init exits by itself, which for a sandbox means the supervisor is gone.
/// `instance-stopped` is its counterpart for a stop issued through the API.
/// The rest keep the pushed snapshot honest across a sandbox's life;
/// `instance-created` also makes a new sandbox known, so its deletion can be
/// reported (see [`DELETED_ACTION`]).
const WATCHED_ACTIONS: &[&str] = &[
    "instance-created",
    "instance-started",
    "instance-shutdown",
    "instance-stopped",
    "instance-restarted",
    "instance-paused",
    "instance-resumed",
];

/// Lifecycle action for a deleted instance. There is nothing left to re-read,
/// so the watcher reports it as a deletion of the sandbox it last knew under
/// that name.
const DELETED_ACTION: &str = "instance-deleted";

/// How many recent events to remember when dropping duplicates.
const RECENT_EVENTS: usize = 64;

/// Recently seen events, to drop the duplicates clustered LXD delivers.
///
/// A clustered LXD (observed on a single-member MicroCloud, LXD 6.9) sends
/// every lifecycle event to a listener twice — same timestamp, same metadata,
/// `lxc monitor` shows it too. Forwarding both would re-read each instance and
/// push each snapshot twice. Two genuinely distinct events never share both
/// the nanosecond timestamp and the metadata, so that pair identifies one.
#[derive(Debug, Default)]
struct RecentEvents {
    keys: VecDeque<String>,
}

impl RecentEvents {
    /// Records `event`, returning `false` if it was already seen.
    fn first_sighting(&mut self, event: &LxdEvent) -> bool {
        let key = format!("{} {}", event.timestamp, event.metadata);
        if self.keys.contains(&key) {
            return false;
        }
        if self.keys.len() == RECENT_EVENTS {
            self.keys.pop_front();
        }
        self.keys.push_back(key);
        true
    }
}

/// Extracts the instance name from a lifecycle event's metadata.
///
/// Prefers the explicit `name` field and falls back to the last segment of
/// `source` (e.g. `/1.0/instances/my-sandbox`), which older LXD releases set
/// without a `name`. Outside the default project `source` carries the
/// project as a query (`/1.0/instances/my-sandbox?project=sandboxes`), which
/// is not part of the name.
fn instance_name(metadata: &serde_json::Value) -> Option<String> {
    if let Some(name) = metadata.get("name").and_then(|v| v.as_str()) {
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    metadata
        .get("source")
        .and_then(|v| v.as_str())
        .and_then(|source| source.split('?').next())
        .and_then(|path| path.rsplit('/').next())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

/// Extracts the lifecycle action (e.g. `instance-shutdown`).
fn action(metadata: &serde_json::Value) -> Option<&str> {
    metadata.get("action").and_then(|v| v.as_str())
}

/// Spawns the lifecycle watcher, which publishes state changes and deletions
/// on `tx` for `WatchSandboxes` to fan out to the gateway in strict order.
///
/// The task reconnects on its own and never terminates, so a subscription
/// failure at start-up (LXD not up yet) is not fatal.
pub(crate) fn spawn(lxd: LxdClient, tx: broadcast::Sender<WatchEvent>) {
    tokio::spawn(async move {
        let mut known_sandbox_ids = HashMap::new();
        loop {
            match run_once(&lxd, &tx, &mut known_sandbox_ids).await {
                Ok(()) => {
                    tracing::debug!("LXD event stream ended; re-subscribing");
                }
                Err(e) => {
                    tracing::warn!(%e, "LXD event stream failed; re-subscribing");
                }
            }
            tokio::time::sleep(RESUBSCRIBE_DELAY).await;
        }
    });
}

/// Sandbox ids of the managed instances currently in the project, by name.
async fn managed_sandbox_ids(
    lxd: &LxdClient,
) -> Result<HashMap<String, String>, lxd_client::LxdError> {
    Ok(lxd
        .list_instances()
        .await?
        .into_iter()
        .filter_map(|instance| {
            let id = instance.config.get(mapping::KEY_SANDBOX_ID)?.clone();
            Some((instance.name, id))
        })
        .collect())
}

/// Reconciles known sandbox IDs against instance listings before and after
/// subscription, returning sandbox IDs that were deleted while disconnected.
fn reconcile_and_seed_sandbox_ids(
    known_sandbox_ids: &mut HashMap<String, String>,
    pre_ids: HashMap<String, String>,
    post_ids: HashMap<String, String>,
) -> Vec<String> {
    let mut deleted_during_gap = Vec::new();
    known_sandbox_ids.retain(|name, id| {
        if !pre_ids.contains_key(name) && !post_ids.contains_key(name) {
            deleted_during_gap.push(id.clone());
            false
        } else {
            true
        }
    });
    // Retain both pre- and post-subscription instances: if an instance
    // present before subscribing was deleted while listing, its queued
    // deletion event will still match the retained entry.
    known_sandbox_ids.extend(pre_ids);
    known_sandbox_ids.extend(post_ids);
    deleted_during_gap
}

/// Subscribes once and forwards events until the stream ends.
async fn run_once(
    lxd: &LxdClient,
    tx: &broadcast::Sender<WatchEvent>,
    known_sandbox_ids: &mut HashMap<String, String>,
) -> Result<(), lxd_client::LxdError> {
    use futures::StreamExt;

    // Snapshot managed instances before subscribing
    let pre_ids = managed_sandbox_ids(lxd).await?;

    let mut stream = lxd.subscribe_events(&["lifecycle"]).await?;
    tracing::debug!("subscribed to LXD lifecycle events");

    // Snapshot managed instances after subscribing
    let post_ids = managed_sandbox_ids(lxd).await?;

    let deleted_during_gap = reconcile_and_seed_sandbox_ids(known_sandbox_ids, pre_ids, post_ids);
    for id in deleted_during_gap {
        tracing::debug!(
            sandbox_id = %id,
            "pushing deletion for sandbox removed during disconnect gap"
        );
        tx.send(WatchEvent::Deleted(id)).ok();
    }

    let mut recent = RecentEvents::default();

    while let Some(event) = stream.next().await {
        let event = event?;
        if !recent.first_sighting(&event) {
            continue;
        }
        let Some(action) = action(&event.metadata) else {
            continue;
        };
        let Some(name) = instance_name(&event.metadata) else {
            continue;
        };

        if action == DELETED_ACTION {
            // Only sandboxes are reported. A delete through DeleteSandbox has
            // already published this; the gateway treats a repeat as a no-op.
            if let Some(sandbox_id) = known_sandbox_ids.remove(&name) {
                tracing::debug!(
                    name = %name,
                    sandbox_id = %sandbox_id,
                    "pushing sandbox deletion from lifecycle event"
                );
                tx.send(WatchEvent::Deleted(sandbox_id)).ok();
            }
            continue;
        }

        if !WATCHED_ACTIONS.contains(&action) {
            continue;
        }

        // Re-read the instance rather than trusting the event: the event says
        // what happened, the instance says what state it left behind, and the
        // snapshot the gateway wants is built from the latter. A sandbox that
        // has since been deleted 404s here and is skipped; its deletion event
        // follows.
        let instance = match lxd.get_instance(&name).await {
            Ok(instance) => instance,
            Err(e) => {
                tracing::debug!(name = %name, %e, "could not read instance for lifecycle event");
                continue;
            }
        };

        // Only driver-managed instances are ours to report on; the event
        // stream carries every instance in the project.
        let Some(sandbox_id) = instance.config.get(mapping::KEY_SANDBOX_ID) else {
            continue;
        };
        known_sandbox_ids.insert(name.clone(), sandbox_id.clone());

        // Off a live event: LXD is up to have sent it, so a stop it announces
        // is the init exiting or one that was asked for, never LXD going down
        // with the daemon or the host.
        let sandbox = mapping::instance_to_driver_sandbox_live(&instance);
        tracing::debug!(
            name = %name,
            action = %action,
            status = %instance.status,
            "pushing sandbox snapshot from lifecycle event"
        );
        // An error here only means nothing is currently watching.
        tx.send(WatchEvent::Sandbox(Box::new(sandbox))).ok();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_name_from_explicit_field() {
        let metadata = json!({"action": "instance-shutdown", "name": "sb-1"});
        assert_eq!(instance_name(&metadata).as_deref(), Some("sb-1"));
        assert_eq!(action(&metadata), Some("instance-shutdown"));
    }

    #[test]
    fn falls_back_to_source_path() {
        let metadata = json!({
            "action": "instance-stopped",
            "source": "/1.0/instances/sb-2",
        });
        assert_eq!(instance_name(&metadata).as_deref(), Some("sb-2"));
    }

    /// LXD appends the project to `source` outside the default project, e.g.
    /// `/1.0/instances/sb-3?project=sandboxes` (observed on LXD 6.9). The
    /// fallback is only taken when `name` is absent, which LXD 6.9 always
    /// sets.
    #[test]
    fn source_fallback_strips_project_query() {
        let metadata = json!({
            "action": "instance-shutdown",
            "source": "/1.0/instances/sb-3?project=sandboxes",
        });
        assert_eq!(instance_name(&metadata).as_deref(), Some("sb-3"));
    }

    #[test]
    fn explicit_name_wins_over_source() {
        let metadata = json!({
            "action": "instance-started",
            "name": "sb-4",
            "source": "/1.0/instances/sb-4?project=sandboxes",
        });
        assert_eq!(instance_name(&metadata).as_deref(), Some("sb-4"));
    }

    #[test]
    fn ignores_events_without_identity() {
        assert_eq!(instance_name(&json!({"action": "instance-shutdown"})), None);
        assert_eq!(instance_name(&json!({"name": ""})), None);
        assert_eq!(action(&json!({})), None);
    }

    #[test]
    fn watches_guest_death_and_api_stop() {
        // The pair that distinguishes "the supervisor exited" from "we were
        // asked to stop it" — the whole point of subscribing.
        assert!(WATCHED_ACTIONS.contains(&"instance-shutdown"));
        assert!(WATCHED_ACTIONS.contains(&"instance-stopped"));
        // Noise that should not trigger a re-read.
        assert!(!WATCHED_ACTIONS.contains(&"instance-log-retrieved"));
        assert!(!WATCHED_ACTIONS.contains(&"image-created"));
    }

    /// A deleted instance cannot be re-read; it is handled separately, by
    /// the sandbox id learned when it was created or first seen.
    #[test]
    fn deletion_is_not_a_re_read_action_but_creation_is() {
        assert!(!WATCHED_ACTIONS.contains(&DELETED_ACTION));
        assert!(WATCHED_ACTIONS.contains(&"instance-created"));
    }

    #[test]
    fn reconcile_detects_deletions_during_disconnect_gap() {
        let mut known = HashMap::from([
            ("sb-survivor".to_string(), "id-survivor".to_string()),
            ("sb-gap-deleted".to_string(), "id-gap-deleted".to_string()),
        ]);

        let pre_ids = HashMap::from([
            ("sb-survivor".to_string(), "id-survivor".to_string()),
            ("sb-new".to_string(), "id-new".to_string()),
        ]);
        let post_ids = HashMap::from([
            ("sb-survivor".to_string(), "id-survivor".to_string()),
            ("sb-new".to_string(), "id-new".to_string()),
        ]);

        let deleted = reconcile_and_seed_sandbox_ids(&mut known, pre_ids, post_ids);
        assert_eq!(deleted, vec!["id-gap-deleted".to_string()]);
        assert_eq!(
            known.get("sb-survivor").map(String::as_str),
            Some("id-survivor")
        );
        assert_eq!(known.get("sb-new").map(String::as_str), Some("id-new"));
        assert!(!known.contains_key("sb-gap-deleted"));
    }

    #[test]
    fn reconcile_preserves_instance_deleted_at_subscribe_boundary() {
        let mut known = HashMap::new();

        // Instance was present before subscribing, but deleted while post_ids was listing
        let pre_ids = HashMap::from([("sb-border".to_string(), "id-border".to_string())]);
        let post_ids = HashMap::new();

        let deleted = reconcile_and_seed_sandbox_ids(&mut known, pre_ids, post_ids);
        // It is not emitted as gap-deleted because its queued lifecycle event will handle it
        assert!(deleted.is_empty());
        // It is retained in known so the queued instance-deleted event can find it
        assert_eq!(
            known.get("sb-border").map(String::as_str),
            Some("id-border")
        );
    }

    fn event(timestamp: &str, action: &str) -> LxdEvent {
        LxdEvent {
            timestamp: timestamp.to_string(),
            type_: "lifecycle".to_string(),
            metadata: json!({"action": action, "name": "sb-5"}),
        }
    }

    #[test]
    fn drops_repeated_events() {
        let mut recent = RecentEvents::default();
        let shutdown = event("2026-09-13T15:56:55.230810123Z", "instance-shutdown");

        assert!(recent.first_sighting(&shutdown));
        assert!(!recent.first_sighting(&shutdown));
        // Same instance and action at another time is a new event, and so is
        // another action at the same time.
        assert!(recent.first_sighting(&event(
            "2026-09-13T15:57:01.000000000Z",
            "instance-shutdown"
        )));
        assert!(recent.first_sighting(&event("2026-09-13T15:56:55.230810123Z", "instance-stopped")));
    }

    #[test]
    fn remembers_a_bounded_number_of_events() {
        let mut recent = RecentEvents::default();
        let first = event("t-0", "instance-started");
        assert!(recent.first_sighting(&first));
        for i in 1..=RECENT_EVENTS {
            assert!(recent.first_sighting(&event(&format!("t-{i}"), "instance-started")));
        }
        assert_eq!(recent.keys.len(), RECENT_EVENTS);
        // Long gone, so no longer recognized.
        assert!(recent.first_sighting(&first));
    }
}
