// SPDX-License-Identifier: AGPL-3.0-or-later

//! Instance (container/VM) lifecycle methods.

use std::collections::HashMap;

use serde_json::json;
use urlencoding::encode;

use crate::client::LxdClient;
use crate::error::LxdError;
use crate::types::{Instance, InstanceState, Operation};

impl LxdClient {
    /// `POST /1.0/instances`: creates an instance from a local image alias.
    ///
    /// When `start` is `true`, LXD starts the instance as part of the same
    /// operation (`InstancesPost.start`), so no separate
    /// [`LxdClient::start_instance`] call is needed for the common
    /// create-and-start case.
    pub async fn create_instance(
        &self,
        name: &str,
        image_alias: &str,
        config: HashMap<String, String>,
        devices: HashMap<String, HashMap<String, String>>,
        profiles: Vec<String>,
        start: bool,
    ) -> Result<Operation, LxdError> {
        let body = json!({
            "name": name,
            "type": "container",
            "source": {
                "type": "image",
                "alias": image_alias,
            },
            "config": config,
            "devices": devices,
            "profiles": profiles,
            "start": start,
        });
        self.post::<Operation>("/1.0/instances", body)
            .await?
            .into_metadata()
    }

    /// `GET /1.0/instances/<name>`.
    pub async fn get_instance(&self, name: &str) -> Result<Instance, LxdError> {
        self.get::<Instance>(&format!("/1.0/instances/{}", encode(name)))
            .await?
            .into_metadata()
    }

    /// `GET /1.0/instances/<name>/state`.
    pub async fn get_instance_state(&self, name: &str) -> Result<InstanceState, LxdError> {
        self.get::<InstanceState>(&format!("/1.0/instances/{}/state", encode(name)))
            .await?
            .into_metadata()
    }

    /// `GET /1.0/instances?recursion=1`.
    pub async fn list_instances(&self) -> Result<Vec<Instance>, LxdError> {
        self.get::<Vec<Instance>>("/1.0/instances?recursion=1")
            .await?
            .into_metadata()
    }

    /// `PUT /1.0/instances/<name>/state` with `{action: "start"}`.
    pub async fn start_instance(&self, name: &str) -> Result<Operation, LxdError> {
        let body = json!({"action": "start"});
        self.put::<Operation>(&format!("/1.0/instances/{}/state", encode(name)), body)
            .await?
            .into_metadata()
    }

    /// `PUT /1.0/instances/<name>/state` with `{action: "stop", force}`.
    ///
    /// Equivalent to [`LxdClient::stop_instance_timeout`] with no deadline: a
    /// graceful stop (`force == false`) then waits indefinitely for the
    /// instance's init to exit.
    pub async fn stop_instance(&self, name: &str, force: bool) -> Result<Operation, LxdError> {
        self.stop_instance_timeout(name, force, 0).await
    }

    /// `PUT /1.0/instances/<name>/state` with `{action: "stop", force, timeout}`.
    ///
    /// `timeout_secs` bounds how long LXD waits for a graceful stop before the
    /// operation fails; `0` means wait forever. Worth setting for any init that
    /// might not act on LXD's shutdown signal, since the operation otherwise
    /// never completes and the instance stays up.
    pub async fn stop_instance_timeout(
        &self,
        name: &str,
        force: bool,
        timeout_secs: i64,
    ) -> Result<Operation, LxdError> {
        let body = json!({"action": "stop", "force": force, "timeout": timeout_secs});
        self.put::<Operation>(&format!("/1.0/instances/{}/state", encode(name)), body)
            .await?
            .into_metadata()
    }

    /// `PATCH /1.0/instances/<name>`: merges `config` into the instance's
    /// configuration, leaving keys that aren't mentioned untouched.
    ///
    /// A `null` value removes the key, which is how a caller clears a marker
    /// it previously set.
    pub async fn patch_instance_config(
        &self,
        name: &str,
        config: HashMap<String, Option<String>>,
    ) -> Result<(), LxdError> {
        let config: serde_json::Map<String, serde_json::Value> = config
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    v.map_or(serde_json::Value::Null, serde_json::Value::String),
                )
            })
            .collect();
        self.patch::<serde_json::Value>(
            &format!("/1.0/instances/{}", encode(name)),
            json!({ "config": config }),
        )
        .await?;
        Ok(())
    }

    /// `DELETE /1.0/instances/<name>`.
    pub async fn delete_instance(&self, name: &str) -> Result<Operation, LxdError> {
        self.delete::<Operation>(&format!("/1.0/instances/{}", encode(name)))
            .await?
            .into_metadata()
    }

    /// `POST /1.0/instances/<name>/files?path=<guest_path>`: write a file
    /// directly into the container's overlay filesystem.
    ///
    /// The container does not need to be running — LXD accesses the overlay
    /// directly for containers (not VMs). The file is created with
    /// `uid=0 gid=0 mode=0400` inside the container (owned by container root,
    /// read-only). This sidesteps the UID-mapping problem that arises when
    /// bind-mounting a host file: a file owned by the host user (e.g. UID 1000)
    /// appears inside an unprivileged container as the overflow UID (65534), which
    /// container root cannot read.
    pub async fn push_file_into_instance(
        &self,
        name: &str,
        guest_path: &str,
        content: &[u8],
    ) -> Result<(), LxdError> {
        self.push_file_into_instance_as(name, guest_path, content, 0, 0, "0400")
            .await
    }

    /// [`Self::push_file_into_instance`], with an explicit owner and mode.
    ///
    /// Anything the workload itself must read has to be owned by the workload's
    /// own uid: it runs unprivileged, so a root-owned `0400` file is invisible
    /// to it. The ids are the container's, not the host's — LXD maps them.
    pub async fn push_file_into_instance_as(
        &self,
        name: &str,
        guest_path: &str,
        content: &[u8],
        uid: u32,
        gid: u32,
        mode: &str,
    ) -> Result<(), LxdError> {
        // LXD's file-push API does not create missing parent directories, so
        // create each ancestor first. The old purpose-built sandbox image
        // shipped the token directory as a placeholder; with arbitrary base
        // images (e.g. the upstream supervisor image) it may not exist.
        self.create_parent_dirs_in_instance(name, guest_path)
            .await?;

        let encoded_path = encode(guest_path);
        self.post_raw(
            &format!("/1.0/instances/{}/files?path={encoded_path}", encode(name)),
            "application/octet-stream",
            &[
                ("X-LXD-uid", uid.to_string().as_str()),
                ("X-LXD-gid", gid.to_string().as_str()),
                ("X-LXD-mode", mode),
                ("X-LXD-type", "file"),
                ("X-LXD-write", "overwrite"),
            ],
            hyper::body::Bytes::copy_from_slice(content),
        )
        .await
    }

    /// Creates one directory inside the container with an explicit owner.
    ///
    /// The workload boundary deletes its own one-use bootstrap after reading
    /// it, which needs write access to the containing directory, not just the
    /// file — so that directory has to belong to the workload, not to root.
    pub async fn create_dir_in_instance_as(
        &self,
        name: &str,
        guest_path: &str,
        uid: u32,
        gid: u32,
        mode: &str,
    ) -> Result<(), LxdError> {
        self.create_parent_dirs_in_instance(name, guest_path)
            .await?;
        let encoded_path = encode(guest_path);
        let result = self
            .post_raw(
                &format!("/1.0/instances/{}/files?path={encoded_path}", encode(name)),
                "application/octet-stream",
                &[
                    ("X-LXD-uid", uid.to_string().as_str()),
                    ("X-LXD-gid", gid.to_string().as_str()),
                    ("X-LXD-mode", mode),
                    ("X-LXD-type", "directory"),
                ],
                hyper::body::Bytes::new(),
            )
            .await;
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.path_is_dir_in_instance(name, guest_path).await {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Creates every ancestor directory of `guest_path` inside the container,
    /// shallowest first, tolerating directories that already exist. Uses the
    /// LXD files API with `X-LXD-type: directory`; the container need not be
    /// running (same overlay-access rules as file push).
    async fn create_parent_dirs_in_instance(
        &self,
        name: &str,
        guest_path: &str,
    ) -> Result<(), LxdError> {
        let mut prefix = String::new();
        let components: Vec<&str> = guest_path.split('/').filter(|c| !c.is_empty()).collect();
        // Skip the last component: it is the file itself, not a directory.
        for component in components.iter().take(components.len().saturating_sub(1)) {
            prefix.push('/');
            prefix.push_str(component);
            let encoded_path = encode(&prefix);
            let result = self
                .post_raw(
                    &format!("/1.0/instances/{}/files?path={encoded_path}", encode(name)),
                    "application/octet-stream",
                    &[
                        ("X-LXD-uid", "0"),
                        ("X-LXD-gid", "0"),
                        ("X-LXD-mode", "0755"),
                        ("X-LXD-type", "directory"),
                    ],
                    hyper::body::Bytes::new(),
                )
                .await;
            match result {
                Ok(()) => {}
                // A directory that already exists is fine. Rather than match
                // on LXD's error wording — which varies by version and would
                // silently swallow unrelated failures that happen to contain
                // the word — ask whether the path is now a directory and only
                // continue if it is.
                Err(e) => {
                    if !self.path_is_dir_in_instance(name, &prefix).await {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    /// True if `guest_path` exists inside the instance and is a directory.
    ///
    /// Used to tell "the directory was already there" apart from a genuine
    /// failure, without depending on the wording of LXD's error message.
    /// Any error answering the question is reported as "not a directory" so
    /// the caller propagates its original, more informative error.
    async fn path_is_dir_in_instance(&self, name: &str, guest_path: &str) -> bool {
        let encoded_path = encode(guest_path);
        let path = format!("/1.0/instances/{}/files?path={encoded_path}", encode(name));
        match self.get_raw_with_headers(&path).await {
            Ok((headers, _)) => {
                headers
                    .get("X-LXD-type")
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    == Some("directory")
            }
            Err(_) => false,
        }
    }

    /// `GET /1.0/instances/<name>/files?path=<guest_path>`: fetches a file from
    /// an instance, returning its content and mode (e.g. `0o755`).
    pub async fn get_file_from_instance(
        &self,
        name: &str,
        guest_path: &str,
    ) -> Result<(hyper::body::Bytes, u32), LxdError> {
        let encoded_path = encode(guest_path);
        let path = format!("/1.0/instances/{}/files?path={encoded_path}", encode(name));
        let (headers, body) = self.get_raw_with_headers(&path).await?;
        let mode_str = headers
            .get("X-LXD-mode")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("0644");
        let clean_mode = mode_str.trim_start_matches('0');
        let mode = if clean_mode.is_empty() {
            0
        } else {
            u32::from_str_radix(clean_mode, 8).unwrap_or(0)
        };
        Ok((body, mode))
    }
}
