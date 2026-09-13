// SPDX-License-Identifier: AGPL-3.0-or-later

//! Image alias lookups, creation, and split image imports.

use std::path::Path;

use serde_json::json;
use tokio::fs::File;
use urlencoding::encode;

use crate::client::LxdClient;
use crate::error::LxdError;
use crate::split_image_body::SplitImageBody;
use crate::types::{Image, Operation};

impl LxdClient {
    /// `GET /1.0/images?recursion=1`: the project's images with their aliases.
    pub async fn list_images(&self) -> Result<Vec<Image>, LxdError> {
        self.get::<Vec<Image>>("/1.0/images?recursion=1")
            .await?
            .into_metadata()
    }

    /// `GET /1.0/images/aliases/<alias>`: true if a local image alias
    /// resolves to an image, false if it doesn't exist.
    pub async fn image_alias_exists(&self, alias: &str) -> Result<bool, LxdError> {
        match self
            .get::<serde_json::Value>(&format!("/1.0/images/aliases/{}", encode(alias)))
            .await
        {
            Ok(_) => Ok(true),
            Err(LxdError::Api {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `GET /1.0/images/<fingerprint>`: returns the aliases associated with an image.
    pub async fn get_image_aliases(&self, fingerprint: &str) -> Result<Vec<String>, LxdError> {
        let response = self
            .get::<serde_json::Value>(&format!("/1.0/images/{}", encode(fingerprint)))
            .await?;
        let metadata = response.into_metadata()?;
        let aliases = metadata
            .get("aliases")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(aliases)
    }

    /// `POST /1.0/images/aliases`: creates an image alias pointing to an existing image fingerprint.
    pub async fn create_image_alias(
        &self,
        alias: &str,
        target_fingerprint: &str,
        description: Option<&str>,
    ) -> Result<(), LxdError> {
        let body = json!({
            "name": alias,
            "target": target_fingerprint,
            "description": description.unwrap_or_default(),
        });
        self.post::<serde_json::Value>("/1.0/images/aliases", body)
            .await?;
        Ok(())
    }

    /// `DELETE /1.0/images/<fingerprint>`: deletes an image from LXD.
    pub async fn delete_image(&self, fingerprint: &str) -> Result<Operation, LxdError> {
        self.delete::<Operation>(&format!("/1.0/images/{}", encode(fingerprint)))
            .await?
            .into_metadata()
    }

    /// `POST /1.0/images`: imports a split image (metadata + rootfs) via multipart/form-data.
    ///
    /// Accepts raw bytes for `metadata` (e.g. `metadata.tar.xz`) and a file path
    /// for `rootfs` (e.g. `rootfs.squashfs` or `rootfs.tar.xz`). Streams the rootfs
    /// directly from disk in bounded chunks to avoid loading multi-gigabyte rootfs
    /// files into memory, and returns an [`Operation`] tracking the import.
    pub async fn create_image_from_split(
        &self,
        metadata_filename: &str,
        metadata_bytes: &[u8],
        rootfs_filename: &str,
        rootfs_path: &Path,
    ) -> Result<Operation, LxdError> {
        let rootfs_meta = tokio::fs::metadata(rootfs_path).await?;
        let rootfs_file = File::open(rootfs_path).await?;
        let boundary = "------------------------openshellsplitimageboundary";

        let body = SplitImageBody::new(
            metadata_filename,
            metadata_bytes,
            rootfs_filename,
            rootfs_file,
            rootfs_meta.len(),
            boundary,
        );

        let content_type = format!("multipart/form-data; boundary={boundary}");
        let response = self
            .post_streaming_response::<Operation>("/1.0/images", &content_type, body)
            .await?;
        response.into_metadata()
    }
}
