// SPDX-License-Identifier: AGPL-3.0-or-later

use lxd_client::LxdError;
use thiserror::Error;
use tonic::Status;

/// Errors produced by [`crate::driver::LxdComputeDriver`].
#[derive(Debug, Error)]
pub enum DriverError {
    /// The requested RPC is not implemented yet.
    #[error("not implemented: {0}")]
    Unimplemented(&'static str),

    /// The request was missing a required field or had an invalid value.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The request is valid but LXD is not set up to serve it, e.g. the
    /// network or storage pool a sandbox is placed on does not exist. The
    /// gateway shows these messages to the user as they are.
    #[error("failed precondition: {0}")]
    FailedPrecondition(String),

    /// The LXD REST API call failed.
    #[error("LXD error: {0}")]
    Lxd(#[from] LxdError),

    /// Waiting for an LXD operation to complete exceeded the configured
    /// deadline.
    #[error("timed out waiting for LXD operation to complete")]
    Timeout,

    /// The named LXD instance exists but isn't managed by this driver (no
    /// `user.openshell.sandbox_id` marker), so it's not found from the
    /// driver's perspective.
    #[error("not found: {0}")]
    NotFound(String),

    /// Image import or reference resolution failed.
    #[error("image import failed: {0}")]
    ImageImport(String),

    /// DHCP client binary was not found or could not be read.
    #[error("DHCP client error: {0}")]
    DhcpClient(String),

    /// An internal driver failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<DriverError> for Status {
    fn from(err: DriverError) -> Self {
        match err {
            DriverError::Internal(msg) => Status::internal(msg),
            DriverError::Unimplemented(msg) => Status::unimplemented(msg),
            DriverError::InvalidArgument(msg) => Status::invalid_argument(msg),
            DriverError::FailedPrecondition(msg) => Status::failed_precondition(msg),
            DriverError::Lxd(LxdError::Api {
                status_code,
                message,
            }) => match status_code {
                400 => Status::invalid_argument(message),
                401 => Status::unauthenticated(message),
                403 => Status::permission_denied(message),
                404 => Status::not_found(message),
                409 => Status::already_exists(message),
                _ => Status::internal(format!(
                    "LXD API error (status code {}): {}",
                    status_code, message
                )),
            },
            DriverError::Lxd(LxdError::InvalidQuantity { quantity, reason }) => {
                Status::invalid_argument(format!(
                    "invalid resource quantity {quantity:?}: {reason}"
                ))
            }
            DriverError::Lxd(lxd_err) => Status::internal(lxd_err.to_string()),
            DriverError::Timeout => {
                Status::deadline_exceeded("timed out waiting for LXD operation to complete")
            }
            DriverError::NotFound(msg) => Status::not_found(msg),
            DriverError::ImageImport(msg) => {
                Status::internal(format!("image import failed: {msg}"))
            }
            DriverError::DhcpClient(msg) => Status::internal(format!("DHCP client error: {msg}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;

    fn api(status_code: u16) -> DriverError {
        DriverError::Lxd(LxdError::Api {
            status_code,
            message: format!("lxd said {status_code}"),
        })
    }

    /// The gateway branches on these codes: `NotFound` means "absent" during
    /// reconcile and delete recovery, `AlreadyExists`/`FailedPrecondition`
    /// pass through to the user, and anything else becomes an internal error.
    #[test]
    fn status_code_follows_error_kind() {
        let cases = [
            (DriverError::Unimplemented("x"), Code::Unimplemented),
            (
                DriverError::InvalidArgument("x".into()),
                Code::InvalidArgument,
            ),
            (
                DriverError::FailedPrecondition("x".into()),
                Code::FailedPrecondition,
            ),
            (DriverError::NotFound("x".into()), Code::NotFound),
            (DriverError::Timeout, Code::DeadlineExceeded),
            (DriverError::ImageImport("x".into()), Code::Internal),
            (api(400), Code::InvalidArgument),
            (api(401), Code::Unauthenticated),
            (api(403), Code::PermissionDenied),
            (api(404), Code::NotFound),
            (api(409), Code::AlreadyExists),
            (api(500), Code::Internal),
            (api(503), Code::Internal),
            (
                DriverError::Lxd(LxdError::InvalidQuantity {
                    quantity: "lots".into(),
                    reason: "not a number".into(),
                }),
                Code::InvalidArgument,
            ),
            (
                DriverError::Lxd(LxdError::OperationFailed {
                    description: "Starting instance".into(),
                    err: "boom".into(),
                }),
                Code::Internal,
            ),
            (
                DriverError::Lxd(LxdError::Io(std::io::Error::other("socket gone"))),
                Code::Internal,
            ),
        ];

        for (err, expected) in cases {
            let rendered = err.to_string();
            let status = Status::from(err);
            assert_eq!(status.code(), expected, "for {rendered}");
        }
    }

    #[test]
    fn status_message_keeps_the_underlying_detail() {
        let status = Status::from(api(409));
        assert_eq!(status.message(), "lxd said 409");

        let status = Status::from(api(500));
        assert!(
            status.message().contains("status code 500")
                && status.message().contains("lxd said 500"),
            "message was {:?}",
            status.message()
        );

        let status = Status::from(DriverError::ImageImport("manifest unknown".into()));
        assert_eq!(status.message(), "image import failed: manifest unknown");

        let status = Status::from(DriverError::Lxd(LxdError::InvalidQuantity {
            quantity: "lots".into(),
            reason: "not a number".into(),
        }));
        assert!(
            status.message().contains("\"lots\""),
            "{:?}",
            status.message()
        );
    }
}
