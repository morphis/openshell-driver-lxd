// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compute extension protocol negotiation, the driver's half.
//!
//! From OpenShell v0.1.0-pre.5 the gateway and every compute driver exchange
//! `PeerMetadata` on `GetCapabilities` and each refuses a peer it cannot
//! interoperate with. This module mirrors upstream's
//! `openshell_core::extension_protocol` closely enough to agree with it, and
//! nothing more: the driver cannot depend on that crate, which is not
//! published, so the contract is reproduced rather than imported.

use computev1::extensionv1::{PeerMetadata, ProtocolVersion};

use crate::error::DriverError;

/// Implementation name this driver negotiates the compute extension protocol
/// under, in upstream's `openshell/<backend>` form.
pub const IMPLEMENTATION_NAME: &str = "canonical/lxd";

/// The extension protocol contract version the gateway negotiates.
///
/// Upstream refuses a driver whose major version differs from its own
/// (`openshell_core::extension_protocol::PROTOCOL_MAJOR`/`PROTOCOL_MINOR`) and
/// requires both peers to advertise the family's contract capability below.
pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL_MINOR: u32 = 0;

/// Capability both peers must support for the compute extension family.
pub const COMPUTE_CONTRACT_CAPABILITY: &str = "openshell.compute.contract";

/// This driver's own protocol metadata, as reported in `GetCapabilities`.
#[must_use]
pub fn driver_metadata() -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: IMPLEMENTATION_NAME.to_string(),
        implementation_version: env!("CARGO_PKG_VERSION").to_string(),
        supported_capabilities: vec![COMPUTE_CONTRACT_CAPABILITY.to_string()],
        required_capabilities: vec![COMPUTE_CONTRACT_CAPABILITY.to_string()],
    }
}

/// The metadata a conforming gateway sends on `GetCapabilities`.
///
/// Reproduced from upstream's `gateway_metadata(ExtensionFamily::Compute)` so
/// tests, and anything else driving this driver's socket directly, present the
/// same thing a gateway does instead of hand-rolling it.
#[must_use]
pub fn gateway_metadata() -> PeerMetadata {
    PeerMetadata {
        protocol_version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        implementation_name: "openshell/gateway".to_string(),
        implementation_version: String::new(),
        supported_capabilities: vec![COMPUTE_CONTRACT_CAPABILITY.to_string()],
        required_capabilities: vec![COMPUTE_CONTRACT_CAPABILITY.to_string()],
    }
}

/// Checks that this driver and the gateway calling it can interoperate.
///
/// Mirrors the gateway's own `negotiate`: an incompatible *major* protocol
/// version is fatal, a newer minor version is not, and each peer must support
/// every capability the other requires. The gateway runs the same check
/// against this driver's metadata and refuses to activate it on failure, so a
/// mismatch is reported here rather than surfacing later as a sandbox that
/// never becomes ready.
pub fn negotiate_with_gateway(
    driver: Option<&PeerMetadata>,
    gateway: Option<&PeerMetadata>,
) -> Result<(), DriverError> {
    let mismatch = |message: String| DriverError::FailedPrecondition(message);
    let gateway = gateway.ok_or_else(|| {
        mismatch(
            "the gateway sent no compute extension protocol metadata; upgrade it and this \
             driver together"
                .to_string(),
        )
    })?;
    let gateway_version = gateway.protocol_version.as_ref().ok_or_else(|| {
        mismatch("the gateway sent no compute extension protocol version".to_string())
    })?;
    if gateway_version.major != PROTOCOL_MAJOR {
        return Err(mismatch(format!(
            "the gateway speaks compute extension protocol {}.{}; this driver speaks \
             {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}",
            gateway_version.major, gateway_version.minor
        )));
    }
    let supported: Vec<&str> = driver
        .map(|metadata| {
            metadata
                .supported_capabilities
                .iter()
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default();
    let missing: Vec<&str> = gateway
        .required_capabilities
        .iter()
        .map(String::as_str)
        .filter(|capability| !supported.contains(capability))
        .collect();
    if !missing.is_empty() {
        return Err(mismatch(format!(
            "the gateway requires compute extension capabilities this driver does not have: {}",
            missing.join(", ")
        )));
    }
    let missing: Vec<&str> = driver
        .map(|metadata| {
            metadata
                .required_capabilities
                .iter()
                .map(String::as_str)
                .filter(|capability| {
                    !gateway
                        .supported_capabilities
                        .iter()
                        .any(|supported| supported == capability)
                })
                .collect()
        })
        .unwrap_or_default();
    if !missing.is_empty() {
        return Err(mismatch(format!(
            "the gateway does not support compute extension capabilities this driver \
             requires: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}
