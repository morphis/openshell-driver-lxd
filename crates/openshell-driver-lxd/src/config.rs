// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::PathBuf;

use clap::Parser;

/// Default path for the gRPC Unix domain socket the OpenShell gateway
/// connects to.
pub const DEFAULT_SOCKET: &str = "/var/run/openshell-driver.sock";

/// Default LXD REST API Unix domain socket (snap install).
pub const DEFAULT_LXD_SOCKET: &str = "/var/snap/lxd/common/lxd/unix.socket";

/// Default tracing log level.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Default sandbox image: the upstream OpenShell community `base` sandbox
/// image. It is resolved and imported on demand through the OCI import path
/// (like any `template.image`), so no image needs to be pre-built or
/// pre-loaded.
///
/// This is deliberately *not* [`DEFAULT_SUPERVISOR_IMAGE`]: the supervisor
/// image ships the `openshell-sandbox` binary on a minimal BusyBox rootfs and
/// is only ever used as the *source* of that binary. It cannot serve as a
/// sandbox rootfs — BusyBox's `ip` has no `netns` subcommand, so the
/// supervisor's proxy mode fails to isolate and exits at boot.
pub const DEFAULT_SANDBOX_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base:latest";

/// Default LXD network sandboxes attach to.
pub const DEFAULT_NETWORK: &str = "lxdbr0";

/// Default LXD storage pool for sandbox root disks.
pub const DEFAULT_STORAGE_POOL: &str = "default";

/// Default LXD project. Re-exported from `lxd_client`.
pub use lxd_client::DEFAULT_PROJECT;

/// Default supervisor OCI image to extract the supervisor binary from.
pub const DEFAULT_SUPERVISOR_IMAGE: &str = "ghcr.io/nvidia/openshell/supervisor:latest";

/// Default host cache directory for extracted supervisor binaries.
pub const DEFAULT_SUPERVISOR_CACHE_DIR: &str = "/var/cache/openshell/lxd-supervisor";

/// Default host scratch directory for OCI image conversion.
///
/// Deliberately disk-backed rather than `TMPDIR`/`/tmp`: converting an image
/// materialises the OCI copy and the unpacked rootfs at the same time, which
/// runs to several gigabytes for a real sandbox image, and `/tmp` is a
/// memory-backed tmpfs on most modern distributions.
pub const DEFAULT_IMAGE_WORK_DIR: &str = "/var/cache/openshell/lxd-image-work";

/// Default deadline, in seconds, for pulling and importing OCI images.
pub const DEFAULT_IMAGE_PULL_TIMEOUT_SECS: u64 = 300;

/// Default `limits.processes` (PID limit) applied to every sandbox container.
///
/// Sandboxes run untrusted agent workloads on a shared host, so an unbounded
/// PID count is a fork-bomb denial of service against co-tenant sandboxes.
/// Set to `0` to leave `pids.max` unlimited.
pub const DEFAULT_MAX_PROCESSES: u32 = 4096;

/// Default number of times to restart a sandbox whose init exits immediately
/// after the first start.
pub const DEFAULT_START_RETRIES: u32 = 1;

/// Default deadline, in seconds, for a graceful sandbox stop before forcing it.
pub const DEFAULT_STOP_TIMEOUT_SECS: i64 = 10;

/// Default gRPC port the gateway listens on.
pub const DEFAULT_GATEWAY_GRPC_PORT: u16 = 17670;

/// Default deadline, in seconds, for waiting on an LXD operation to complete.
pub const DEFAULT_OPERATION_TIMEOUT_SECS: u64 = 60;

/// Default prefix for digest-derived LXD image aliases.
pub const DEFAULT_IMAGE_CACHE_ALIAS_PREFIX: &str = "openshell-oci-";

/// CLI configuration for `openshell-driver-lxd`.
#[derive(Debug, Clone, Parser)]
#[command(name = "openshell-driver-lxd", version, about)]
pub struct Config {
    /// Path to the Unix domain socket the gRPC server listens on.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    pub socket: PathBuf,

    /// Path to the LXD REST API Unix domain socket (local snap installation).
    /// Ignored when --lxd-url is set.
    #[arg(long, default_value = DEFAULT_LXD_SOCKET)]
    pub lxd_socket: PathBuf,

    /// Tracing log level (e.g. "trace", "debug", "info", "warn", "error").
    #[arg(long, default_value = DEFAULT_LOG_LEVEL)]
    pub log_level: String,

    /// OCI image reference every sandbox is created from when the request's
    /// `template.image` is empty. Resolved and imported on demand.
    #[arg(long, default_value = DEFAULT_SANDBOX_IMAGE)]
    pub default_image: String,

    /// LXD project to target for all instances, images, networks, and
    /// operations. The project must already exist; the driver will not create
    /// it.
    #[arg(long, default_value = DEFAULT_PROJECT)]
    pub project: String,

    /// LXD network sandboxes attach to unless a request sets
    /// `driver_config.network`. On MicroCloud this is typically the OVN
    /// network `default`.
    #[arg(long, default_value = DEFAULT_NETWORK)]
    pub default_network: String,

    /// LXD storage pool for sandbox root disks unless a request sets
    /// `driver_config.storage_pool`. On MicroCloud this is typically `local`
    /// or `remote`.
    #[arg(long, default_value = DEFAULT_STORAGE_POOL)]
    pub default_storage_pool: String,

    /// OCI image reference to extract the OpenShell supervisor binary from.
    #[arg(long, default_value = DEFAULT_SUPERVISOR_IMAGE)]
    pub supervisor_image: String,

    /// Optional path to a pre-extracted OpenShell supervisor binary on the host.
    /// When set, skips extracting the binary from the supervisor OCI image.
    #[arg(long)]
    pub supervisor_bin: Option<PathBuf>,

    /// Optional path to a DHCP client binary on the host (e.g. `udhcpc` or `busybox`).
    /// When unset, the driver searches PATH and standard system locations.
    #[arg(long, alias = "udhcpc-path")]
    pub dhcp_client_bin: Option<PathBuf>,

    /// Host cache directory where extracted supervisor binaries are stored,
    /// keyed by content digest.
    #[arg(long, default_value = DEFAULT_SUPERVISOR_CACHE_DIR)]
    pub supervisor_cache_dir: PathBuf,

    /// LXD storage pool where supervisor and DHCP-client custom storage
    /// volumes are created. When unset, each sandbox's own storage pool
    /// (`driver_config.storage_pool`, itself defaulting to `default`) is
    /// used, so the auxiliary volumes always live alongside the rootfs they
    /// are attached to. Set this to pin every auxiliary volume to one pool.
    #[arg(long)]
    pub supervisor_storage_pool: Option<String>,

    /// Host scratch directory for OCI image conversion. Needs room for the
    /// OCI copy plus the unpacked rootfs (several GiB for a real sandbox
    /// image), so it must not be a small tmpfs such as `/tmp`.
    #[arg(long, default_value = DEFAULT_IMAGE_WORK_DIR)]
    pub image_work_dir: PathBuf,

    /// `limits.processes` applied to every sandbox container, bounding the
    /// PID count a sandbox can consume. `0` leaves it unlimited.
    /// Overridable per sandbox via `driver_config.max_processes`.
    #[arg(long, default_value_t = DEFAULT_MAX_PROCESSES)]
    pub default_max_processes: u32,

    /// Number of times to restart a sandbox whose init exits immediately
    /// after the first start (e.g. a supervisor that lost a start-up race
    /// with the gateway). `0` disables the retry.
    #[arg(long, default_value_t = DEFAULT_START_RETRIES)]
    pub start_retries: u32,

    /// Deadline, in seconds, to wait for a sandbox to shut down gracefully
    /// before stopping it forcibly. The supervisor does not act on LXD's
    /// shutdown signal today, so this is how long each stop waits before the
    /// forced stop that actually ends it.
    #[arg(long, default_value_t = DEFAULT_STOP_TIMEOUT_SECS)]
    pub stop_timeout_secs: i64,

    /// Deadline, in seconds, for pulling and importing OCI images before failing.
    #[arg(long, default_value_t = DEFAULT_IMAGE_PULL_TIMEOUT_SECS)]
    pub image_pull_timeout_secs: u64,
    /// Prefix for digest-derived LXD image aliases.
    #[arg(long, default_value = DEFAULT_IMAGE_CACHE_ALIAS_PREFIX)]
    pub image_cache_alias_prefix: String,

    /// Optional path override for the skopeo binary.
    #[arg(long)]
    pub skopeo_path: Option<PathBuf>,

    /// Optional path override for the umoci binary.
    #[arg(long)]
    pub umoci_path: Option<PathBuf>,

    /// Optional path override for the mksquashfs binary.
    #[arg(long)]
    pub mksquashfs_path: Option<PathBuf>,

    /// Remote LXD HTTPS endpoint (e.g. https://10.0.0.1:8443).
    /// When set, --lxd-socket is ignored and HTTPS+mTLS is used instead.
    #[arg(long, requires_all = ["lxd_client_cert", "lxd_client_key"])]
    pub lxd_url: Option<String>,

    /// PEM client certificate for mTLS to a remote LXD (requires --lxd-url).
    #[arg(long, requires_all = ["lxd_url", "lxd_client_key"])]
    pub lxd_client_cert: Option<PathBuf>,

    /// PEM client private key for mTLS to a remote LXD (requires --lxd-url).
    #[arg(long, requires_all = ["lxd_url", "lxd_client_cert"])]
    pub lxd_client_key: Option<PathBuf>,

    /// PEM CA certificate to verify the remote LXD server cert.
    /// Omit to use the built-in webpki CA bundle.
    #[arg(long, requires = "lxd_url")]
    pub lxd_server_ca: Option<PathBuf>,

    /// gRPC port the gateway listens on, used to build OPENSHELL_ENDPOINT for
    /// sandboxes. The host is resolved from the sandbox's own LXD bridge
    /// network at create time.
    #[arg(long, default_value_t = DEFAULT_GATEWAY_GRPC_PORT)]
    pub gateway_grpc_port: u16,

    /// Deadline, in seconds, to wait for an LXD operation to complete before
    /// failing the RPC with DeadlineExceeded.
    #[arg(long, default_value_t = DEFAULT_OPERATION_TIMEOUT_SECS)]
    pub operation_timeout_secs: u64,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        Config::command().debug_assert();
    }

    #[test]
    fn defaults_parse_without_arguments() {
        let config = Config::parse_from(["openshell-driver-lxd"]);

        assert_eq!(config.socket, PathBuf::from(DEFAULT_SOCKET));
        assert_eq!(config.project, DEFAULT_PROJECT);
        assert_eq!(config.default_network, DEFAULT_NETWORK);
        assert_eq!(config.default_storage_pool, DEFAULT_STORAGE_POOL);
        assert_eq!(config.default_image, DEFAULT_SANDBOX_IMAGE);
        assert_eq!(config.supervisor_image, DEFAULT_SUPERVISOR_IMAGE);
        assert!(config.supervisor_bin.is_none());
        assert!(config.lxd_url.is_none());
        assert_eq!(config.gateway_grpc_port, DEFAULT_GATEWAY_GRPC_PORT);
    }

    /// A graceful stop always runs to its deadline (the supervisor ignores
    /// LXD's shutdown signal), and each stop step is itself bounded by the
    /// operation timeout, so the graceful deadline must fit inside it or the
    /// forced stop never gets a chance to run.
    #[test]
    fn graceful_stop_deadline_fits_inside_operation_timeout() {
        let config = Config::parse_from(["openshell-driver-lxd"]);
        let stop_timeout = u64::try_from(config.stop_timeout_secs).expect("positive default");

        assert!(stop_timeout > 0);
        assert!(
            stop_timeout < config.operation_timeout_secs,
            "stop timeout {stop_timeout}s must be shorter than the operation timeout {}s",
            config.operation_timeout_secs
        );
    }

    /// Image conversion materializes several GiB; the default must not sit on
    /// the memory-backed temp directory.
    #[test]
    fn default_image_work_dir_is_not_the_temp_dir() {
        let work_dir = PathBuf::from(DEFAULT_IMAGE_WORK_DIR);

        assert!(work_dir.is_absolute());
        assert!(!work_dir.starts_with("/tmp"));
        assert!(!work_dir.starts_with(std::env::temp_dir()));
    }

    #[test]
    fn remote_lxd_requires_client_certificate_and_key() {
        let missing_key = Config::try_parse_from([
            "openshell-driver-lxd",
            "--lxd-url",
            "https://10.0.0.1:8443",
            "--lxd-client-cert",
            "/etc/cert.pem",
        ]);
        assert!(missing_key.is_err());

        let complete = Config::try_parse_from([
            "openshell-driver-lxd",
            "--lxd-url",
            "https://10.0.0.1:8443",
            "--lxd-client-cert",
            "/etc/cert.pem",
            "--lxd-client-key",
            "/etc/key.pem",
        ])
        .expect("url with cert and key should parse");
        assert_eq!(complete.lxd_url.as_deref(), Some("https://10.0.0.1:8443"));
    }

    #[test]
    fn server_ca_is_only_meaningful_with_a_remote_url() {
        let result =
            Config::try_parse_from(["openshell-driver-lxd", "--lxd-server-ca", "/etc/ca.pem"]);
        assert!(result.is_err());
    }
}
