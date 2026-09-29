// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network lookups.

use urlencoding::encode;

use crate::client::LxdClient;
use crate::error::LxdError;
use crate::types::Network;

impl LxdClient {
    /// `GET /1.0/networks/<name>`.
    pub async fn get_network(&self, name: &str) -> Result<Network, LxdError> {
        self.get::<Network>(&format!("/1.0/networks/{}", encode(name)))
            .await?
            .into_metadata()
    }
}
