// SPDX-License-Identifier: AGPL-3.0-or-later

//! Custom storage volume management on LXD storage pools.

use std::path::Path;

use hyper::body::Bytes;
use serde_json::json;
use urlencoding::encode;

use crate::client::LxdClient;
use crate::error::LxdError;
use crate::types::{Operation, StorageVolume};

impl LxdClient {
    /// `GET /1.0/storage-pools`: the names of the storage pools.
    pub async fn list_storage_pools(&self) -> Result<Vec<String>, LxdError> {
        let paths = self
            .get::<Vec<String>>("/1.0/storage-pools")
            .await?
            .into_metadata()?;
        Ok(paths
            .iter()
            .filter_map(|path| path.rsplit('/').next())
            .map(|name| {
                urlencoding::decode(name).map_or_else(|_| name.to_string(), |n| n.into_owned())
            })
            .collect())
    }

    /// The project's custom volumes on `pool`, with what uses them and, on a
    /// cluster, the member each lives on.
    pub async fn list_custom_volumes(&self, pool: &str) -> Result<Vec<StorageVolume>, LxdError> {
        self.get::<Vec<StorageVolume>>(&format!(
            "/1.0/storage-pools/{}/volumes/custom?recursion=1",
            encode(pool)
        ))
        .await?
        .into_metadata()
    }

    /// Deletes a custom volume, on cluster member `location` when the pool
    /// keeps a volume per member (empty `location` otherwise), and waits for
    /// the deletion to finish.
    pub async fn delete_custom_volume(
        &self,
        pool: &str,
        name: &str,
        location: &str,
    ) -> Result<(), LxdError> {
        let mut path = format!(
            "/1.0/storage-pools/{}/volumes/custom/{}",
            encode(pool),
            encode(name)
        );
        if !location.is_empty() {
            path.push_str(&format!("?target={}", encode(location)));
        }
        let response = self.delete::<serde_json::Value>(&path).await?;
        // Deleting a custom volume answers synchronously on current LXD; an
        // asynchronous answer carries the operation to wait on.
        if response.type_ == "async" {
            let op: Operation = serde_json::from_value(response.into_metadata()?)?;
            self.wait_operation(&op.id).await?;
        }
        Ok(())
    }

    /// Checks whether a storage pool exists.
    pub async fn storage_pool_exists(&self, pool: &str) -> Result<bool, LxdError> {
        let path = format!("/1.0/storage-pools/{}", encode(pool));
        match self.get::<serde_json::Value>(&path).await {
            Ok(_) => Ok(true),
            Err(LxdError::Api {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Checks whether a custom storage pool volume exists on the given pool.
    pub async fn storage_pool_volume_exists(
        &self,
        pool: &str,
        volume_type: &str,
        name: &str,
    ) -> Result<bool, LxdError> {
        let path = format!(
            "/1.0/storage-pools/{}/volumes/{}/{}",
            encode(pool),
            encode(volume_type),
            encode(name)
        );
        match self.get::<serde_json::Value>(&path).await {
            Ok(_) => Ok(true),
            Err(LxdError::Api {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Creates a custom storage volume from a tarball payload on the given storage pool.
    ///
    /// Sends a `POST /1.0/storage-pools/<pool>/volumes` with the raw tarball
    /// and `X-LXD-name: <name>`.
    pub async fn create_storage_pool_volume_from_tarball(
        &self,
        pool: &str,
        name: &str,
        tarball_bytes: &[u8],
    ) -> Result<Operation, LxdError> {
        let path = format!("/1.0/storage-pools/{}/volumes", encode(pool));
        let response = self
            .post_raw_response::<Operation>(
                &path,
                "application/octet-stream",
                &[("X-LXD-name", name), ("X-LXD-type", "tar")],
                Bytes::copy_from_slice(tarball_bytes),
            )
            .await?;
        response.into_metadata()
    }

    /// Updates custom storage pool volume configuration (e.g. setting `security.shifted`).
    pub async fn update_storage_pool_volume_config(
        &self,
        pool: &str,
        volume_type: &str,
        name: &str,
        config: serde_json::Value,
    ) -> Result<Operation, LxdError> {
        let path = format!(
            "/1.0/storage-pools/{}/volumes/{}/{}",
            encode(pool),
            encode(volume_type),
            encode(name)
        );
        let body = json!({
            "config": config,
        });
        let response = self.patch::<Operation>(&path, body).await?;
        response.into_metadata()
    }

    /// Fetches custom storage pool volume metadata.
    pub async fn get_storage_pool_volume(
        &self,
        pool: &str,
        volume_type: &str,
        name: &str,
    ) -> Result<serde_json::Value, LxdError> {
        let path = format!(
            "/1.0/storage-pools/{}/volumes/{}/{}",
            encode(pool),
            encode(volume_type),
            encode(name)
        );
        let response = self.get::<serde_json::Value>(&path).await?;
        response.into_metadata()
    }

    /// Reconciles storage volume configuration, ensuring `security.shifted: true` is applied.
    pub async fn ensure_storage_pool_volume_shifted(
        &self,
        pool: &str,
        volume_type: &str,
        name: &str,
    ) -> Result<(), LxdError> {
        let volume = self
            .get_storage_pool_volume(pool, volume_type, name)
            .await?;
        let is_shifted = volume
            .get("config")
            .and_then(|c| c.get("security.shifted"))
            .and_then(|v| v.as_str())
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if !is_shifted {
            let config = json!({
                "security.shifted": "true",
            });
            let op = self
                .update_storage_pool_volume_config(pool, volume_type, name, config)
                .await?;
            self.wait_operation(&op.id).await?;
        }
        Ok(())
    }

    /// Deletes a custom storage pool volume.
    pub async fn delete_storage_pool_volume(
        &self,
        pool: &str,
        volume_type: &str,
        name: &str,
    ) -> Result<Operation, LxdError> {
        let path = format!(
            "/1.0/storage-pools/{}/volumes/{}/{}",
            encode(pool),
            encode(volume_type),
            encode(name)
        );
        let response = self.delete::<Operation>(&path).await?;
        response.into_metadata()
    }

    /// Ensures a digest-keyed supervisor storage volume exists on `pool`.
    ///
    /// Packages `binary` into a single-entry tarball containing `openshell-sandbox`,
    /// creates the volume with `content-type: filesystem` and `security.shifted: true`,
    /// and treats losing a creation race as success.
    pub async fn ensure_supervisor_volume(
        &self,
        pool: &str,
        name: &str,
        binary: &Path,
    ) -> Result<(), LxdError> {
        #[cfg(unix)]
        let binary_bytes = {
            let mut file = tokio::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(binary)
                .await?;
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut file, &mut buf).await?;
            buf
        };
        #[cfg(not(unix))]
        let binary_bytes = tokio::fs::read(binary).await?;

        self.ensure_single_file_volume(pool, name, &[("openshell-sandbox", &binary_bytes, 0o755)])
            .await
    }

    /// Ensures a digest-keyed DHCP client storage volume exists on `pool`.
    ///
    /// Packages `binary_bytes` as `udhcpc` and `script_bytes` as `udhcpc.script`,
    /// creates the volume with `content-type: filesystem` and `security.shifted: true`,
    /// and treats losing a creation race as success.
    pub async fn ensure_dhcp_client_volume(
        &self,
        pool: &str,
        name: &str,
        binary_bytes: &[u8],
        script_bytes: &[u8],
    ) -> Result<(), LxdError> {
        self.ensure_single_file_volume(
            pool,
            name,
            &[
                ("udhcpc", binary_bytes, 0o755),
                ("udhcpc.script", script_bytes, 0o755),
            ],
        )
        .await
    }

    /// Ensures a digest-keyed storage volume exists on `pool` containing the given file entries.
    ///
    /// Packages `entries` into a tarball and creates the volume with
    /// `content-type: filesystem` and `security.shifted: true`.
    ///
    /// Concurrent creators are expected: if creation fails, the volume is
    /// re-probed and a volume that now exists counts as success, so the
    /// outcome does not depend on the wording of LXD's error.
    pub async fn ensure_single_file_volume(
        &self,
        pool: &str,
        name: &str,
        entries: &[(&str, &[u8], u32)],
    ) -> Result<(), LxdError> {
        if self
            .storage_pool_volume_exists(pool, "custom", name)
            .await?
        {
            tracing::debug!(pool = %pool, name = %name, "storage volume already exists; ensuring shifted configuration");
            return self
                .ensure_storage_pool_volume_shifted(pool, "custom", name)
                .await;
        }

        let tarball_bytes = create_multi_file_tarball(entries)?;

        let created = match self
            .create_storage_pool_volume_from_tarball(pool, name, &tarball_bytes)
            .await
        {
            Ok(op) => self.wait_operation(&op.id).await.map(|_| ()),
            Err(e) => Err(e),
        };

        if let Err(e) = created {
            // Another creator winning the race is success, not failure. Ask
            // the API whether the volume is there now instead of matching on
            // the error's wording, which differs between a synchronous 409, an
            // async operation failure, and LXD versions.
            if self
                .storage_pool_volume_exists(pool, "custom", name)
                .await?
            {
                tracing::debug!(
                    pool = %pool,
                    name = %name,
                    "volume creation raced; volume already exists; ensuring shifted configuration"
                );
                return self
                    .ensure_storage_pool_volume_shifted(pool, "custom", name)
                    .await;
            }
            return Err(e);
        }

        // Configure security.shifted: true so unprivileged containers can access the files
        self.ensure_storage_pool_volume_shifted(pool, "custom", name)
            .await?;

        Ok(())
    }
}

/// Helper to create an in-memory tarball containing multiple files at root.
pub(crate) fn create_multi_file_tarball(
    entries: &[(&str, &[u8], u32)],
) -> Result<Vec<u8>, std::io::Error> {
    let mut builder = tar::Builder::new(Vec::new());
    for (filename, contents, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(*mode);
        header.set_cksum();
        builder.append_data(&mut header, *filename, *contents)?;
    }
    builder.into_inner()
}

/// Helper to create an in-memory tarball containing a single file at root.
#[cfg(test)]
pub(crate) fn create_single_file_tarball(
    filename: &str,
    contents: &[u8],
    mode: u32,
) -> Result<Vec<u8>, std::io::Error> {
    create_multi_file_tarball(&[(filename, contents, mode)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_single_file_tarball() {
        let content = b"echo hello world";
        let tar_bytes = create_single_file_tarball("openshell-sandbox", content, 0o755).unwrap();

        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let mut entries = archive.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().to_str().unwrap(), "openshell-sandbox");
        assert_eq!(entry.header().mode().unwrap(), 0o755);

        let mut extracted = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut extracted).unwrap();
        assert_eq!(extracted, content);
        assert!(entries.next().is_none());
    }

    #[test]
    fn test_create_multi_file_tarball() {
        let bin_content = b"fake-binary";
        let script_content = b"#!/bin/sh\necho test\n";
        let tar_bytes = create_multi_file_tarball(&[
            ("udhcpc", bin_content, 0o755),
            ("udhcpc.script", script_content, 0o755),
        ])
        .unwrap();

        let mut archive = tar::Archive::new(&tar_bytes[..]);
        let mut entries = archive.entries().unwrap();

        let mut entry1 = entries.next().unwrap().unwrap();
        assert_eq!(entry1.path().unwrap().to_str().unwrap(), "udhcpc");
        assert_eq!(entry1.header().mode().unwrap(), 0o755);
        let mut extracted1 = Vec::new();
        std::io::Read::read_to_end(&mut entry1, &mut extracted1).unwrap();
        assert_eq!(extracted1, bin_content);

        let mut entry2 = entries.next().unwrap().unwrap();
        assert_eq!(entry2.path().unwrap().to_str().unwrap(), "udhcpc.script");
        assert_eq!(entry2.header().mode().unwrap(), 0o755);
        let mut extracted2 = Vec::new();
        std::io::Read::read_to_end(&mut entry2, &mut extracted2).unwrap();
        assert_eq!(extracted2, script_content);

        assert!(entries.next().is_none());
    }
}
