// SPDX-License-Identifier: AGPL-3.0-or-later

use std::path::{Path, PathBuf};

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
    /// sandboxes when --gateway-endpoint is unset. The host is then resolved
    /// from the sandbox's own LXD bridge network at create time.
    #[arg(long, default_value_t = DEFAULT_GATEWAY_GRPC_PORT)]
    pub gateway_grpc_port: u16,

    /// URL sandboxes reach the gateway at (OPENSHELL_ENDPOINT), e.g.
    /// `http://10.0.0.5:17670`. When unset, it is the host-side address of the
    /// sandbox's network plus --gateway-grpc-port, which only reaches a gateway
    /// listening on that bridge. Set it when the gateway runs anywhere else —
    /// in an instance, on another machine — and on OVN networks, whose
    /// address belongs to their virtual router.
    #[arg(long, value_parser = parse_gateway_endpoint)]
    pub gateway_endpoint: Option<String>,

    /// Set `security.nesting` on sandboxes, for workloads that run containers
    /// themselves. The supervisor does not need it: its network namespace,
    /// nftables rules and seccomp filter work without. Nesting relaxes the
    /// container's AppArmor confinement, and a restricted project refuses it
    /// unless `restricted.containers.nesting=allow`.
    #[arg(long)]
    pub sandbox_nesting: bool,

    /// PEM CA certificate sandboxes verify the gateway's certificate against.
    /// Copied into every sandbox, with --guest-tls-cert and --guest-tls-key,
    /// for the supervisor's mutual-TLS connection to the gateway; the
    /// gateway endpoint is then `https`. Read on every create, so rotated
    /// files reach new sandboxes.
    #[arg(long, requires_all = ["guest_tls_cert", "guest_tls_key"])]
    pub guest_tls_ca: Option<PathBuf>,

    /// PEM client certificate sandboxes present to the gateway.
    #[arg(long, requires_all = ["guest_tls_ca", "guest_tls_key"])]
    pub guest_tls_cert: Option<PathBuf>,

    /// PEM private key of --guest-tls-cert.
    #[arg(long, requires_all = ["guest_tls_ca", "guest_tls_cert"])]
    pub guest_tls_key: Option<PathBuf>,

    /// Let sandboxes reach the gateway over plaintext HTTP instead of TLS.
    /// Sandbox tokens, policy and credentials then cross the network
    /// unencrypted, so this is only for local testing.
    #[arg(long, conflicts_with_all = ["guest_tls_ca", "guest_tls_cert", "guest_tls_key"])]
    pub allow_plaintext_gateway: bool,

    /// Deadline, in seconds, to wait for an LXD operation to complete before
    /// failing the RPC with DeadlineExceeded.
    #[arg(long, default_value_t = DEFAULT_OPERATION_TIMEOUT_SECS)]
    pub operation_timeout_secs: u64,
}

/// Host paths of the TLS materials sandboxes connect to the gateway with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestTls<'a> {
    pub ca: &'a Path,
    pub cert: &'a Path,
    pub key: &'a Path,
}

impl Config {
    /// The TLS materials for sandboxes, when configured.
    #[must_use]
    pub fn guest_tls(&self) -> Option<GuestTls<'_>> {
        Some(GuestTls {
            ca: self.guest_tls_ca.as_deref()?,
            cert: self.guest_tls_cert.as_deref()?,
            key: self.guest_tls_key.as_deref()?,
        })
    }

    /// Scheme of the gateway endpoint the driver derives from a network.
    #[must_use]
    pub fn gateway_scheme(&self) -> &'static str {
        if self.guest_tls().is_some() {
            "https"
        } else {
            "http"
        }
    }

    /// Checks that sandboxes will reach the gateway over TLS, or that
    /// plaintext was explicitly allowed, and that `--gateway-endpoint`
    /// agrees. clap enforces the rest (all three TLS files or none, and not
    /// alongside `--allow-plaintext-gateway`).
    pub fn validate(&self) -> Result<(), String> {
        let tls = self.guest_tls().is_some();
        if !tls && !self.allow_plaintext_gateway {
            return Err(
                "sandboxes connect to the gateway over TLS: set --guest-tls-ca, \
                 --guest-tls-cert and --guest-tls-key (--allow-plaintext-gateway permits a \
                 plaintext gateway for local testing)"
                    .to_string(),
            );
        }
        match self.gateway_endpoint.as_deref() {
            Some(endpoint) if tls && !endpoint.starts_with("https://") => Err(format!(
                "--gateway-endpoint {endpoint} is not https, but sandboxes are given TLS \
                 materials; use an https:// endpoint"
            )),
            Some(endpoint) if !tls && !endpoint.starts_with("http://") => Err(format!(
                "--gateway-endpoint {endpoint} is https, which needs --guest-tls-ca, \
                 --guest-tls-cert and --guest-tls-key"
            )),
            _ => Ok(()),
        }
    }
}

/// Validates `--gateway-endpoint`: an `http` or `https` URL naming a host and
/// nothing past the port, which is all the supervisor uses. Returns it
/// normalized (lowercase scheme and host, no surrounding whitespace) and
/// without a trailing slash.
fn parse_gateway_endpoint(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!(
            "scheme must be http or https, not {:?}",
            url.scheme()
        ));
    }
    if !url.host_str().is_some_and(|host| !host.is_empty()) {
        return Err("the URL names no host".to_string());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("the URL must not have a path, query or fragment".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the URL must not carry credentials".to_string());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
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
        assert!(config.gateway_endpoint.is_none());
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
    fn gateway_endpoint_is_an_http_or_https_url() {
        for (value, expected) in [
            ("http://10.0.0.5:17670", "http://10.0.0.5:17670"),
            (
                "https://gateway.example:17670/",
                "https://gateway.example:17670",
            ),
            ("https://[fd42::5]:17670", "https://[fd42::5]:17670"),
            (
                " HTTPS://Gateway.Example:17670/ ",
                "https://gateway.example:17670",
            ),
        ] {
            let config =
                Config::try_parse_from(["openshell-driver-lxd", "--gateway-endpoint", value])
                    .unwrap_or_else(|e| panic!("{value}: {e}"));
            assert_eq!(config.gateway_endpoint.as_deref(), Some(expected));
        }

        for value in [
            "10.0.0.5:17670",
            "grpc://10.0.0.5:17670",
            "http://10.0.0.5:17670/api",
            "http://user:secret@10.0.0.5:17670",
            "file:///tmp/sock",
        ] {
            assert!(
                Config::try_parse_from(["openshell-driver-lxd", "--gateway-endpoint", value])
                    .is_err(),
                "{value} should be rejected"
            );
        }
    }

    const TLS_ARGS: [&str; 6] = [
        "--guest-tls-ca",
        "/etc/openshell/tls/ca.crt",
        "--guest-tls-cert",
        "/etc/openshell/tls/client/tls.crt",
        "--guest-tls-key",
        "/etc/openshell/tls/client/tls.key",
    ];

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(std::iter::once("openshell-driver-lxd").chain(args.iter().copied()))
    }

    #[test]
    fn tls_to_the_gateway_is_required_unless_plaintext_is_allowed() {
        let neither = parse(&[]).unwrap();
        assert!(neither.validate().is_err());

        let tls = parse(&TLS_ARGS).unwrap();
        assert_eq!(tls.validate(), Ok(()));
        assert_eq!(tls.gateway_scheme(), "https");
        assert_eq!(
            tls.guest_tls(),
            Some(GuestTls {
                ca: Path::new("/etc/openshell/tls/ca.crt"),
                cert: Path::new("/etc/openshell/tls/client/tls.crt"),
                key: Path::new("/etc/openshell/tls/client/tls.key"),
            })
        );

        let plaintext = parse(&["--allow-plaintext-gateway"]).unwrap();
        assert_eq!(plaintext.validate(), Ok(()));
        assert_eq!(plaintext.gateway_scheme(), "http");
        assert_eq!(plaintext.guest_tls(), None);
    }

    #[test]
    fn tls_materials_come_together_and_not_with_plaintext() {
        assert!(parse(&TLS_ARGS[..4]).is_err());
        assert!(parse(&["--guest-tls-key", "/k"]).is_err());

        let mut both = TLS_ARGS.to_vec();
        both.push("--allow-plaintext-gateway");
        assert!(parse(&both).is_err());
    }

    #[test]
    fn gateway_endpoint_scheme_matches_the_transport() {
        let mut tls_https = TLS_ARGS.to_vec();
        tls_https.extend(["--gateway-endpoint", "https://10.0.0.5:17670"]);
        assert_eq!(parse(&tls_https).unwrap().validate(), Ok(()));

        let mut tls_http = TLS_ARGS.to_vec();
        tls_http.extend(["--gateway-endpoint", "http://10.0.0.5:17670"]);
        assert!(parse(&tls_http).unwrap().validate().is_err());

        let plaintext_https = parse(&[
            "--allow-plaintext-gateway",
            "--gateway-endpoint",
            "https://10.0.0.5:17670",
        ])
        .unwrap();
        assert!(plaintext_https.validate().is_err());

        let plaintext_http = parse(&[
            "--allow-plaintext-gateway",
            "--gateway-endpoint",
            "http://10.0.0.5:17670",
        ])
        .unwrap();
        assert_eq!(plaintext_http.validate(), Ok(()));
    }

    #[test]
    fn server_ca_is_only_meaningful_with_a_remote_url() {
        let result =
            Config::try_parse_from(["openshell-driver-lxd", "--lxd-server-ca", "/etc/ca.pem"]);
        assert!(result.is_err());
    }
}
