// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use clap::Parser;
use computev1::pb::compute_driver_server::ComputeDriverServer;
use lxd_client::{LxdClient, LxdEndpoint, LxdHttpsConfig};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use openshell_driver_lxd::config::Config;
use openshell_driver_lxd::driver::LxdComputeDriver;
use openshell_driver_lxd::grpc::ComputeDriverService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level)),
        )
        .init();

    // Refuse a configuration that would hand sandboxes a plaintext gateway
    // nobody asked for, before binding the socket the gateway connects to.
    if let Err(e) = config.validate() {
        error!("{e}");
        std::process::exit(2);
    }
    if let Some(tls) = config.guest_tls() {
        for path in [tls.ca, tls.cert, tls.key] {
            if let Err(e) = fs::File::open(path) {
                error!(path = %path.display(), %e, "cannot read sandbox TLS material");
                std::process::exit(2);
            }
        }
    } else {
        warn!("sandboxes reach the gateway over plaintext HTTP (--allow-plaintext-gateway)");
    }

    if let Some(parent) = config.socket.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    match fs::symlink_metadata(&config.socket) {
        Ok(metadata) => {
            if metadata.file_type().is_socket() {
                fs::remove_file(&config.socket)?;
            } else {
                return Err(format!(
                    "refusing to remove existing non-socket path at {}",
                    config.socket.display()
                )
                .into());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let listener = UnixListener::bind(&config.socket)?;
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o600))?;

    let endpoint = if let Some(url) = config.lxd_url.clone() {
        let client_cert = config
            .lxd_client_cert
            .clone()
            .ok_or("--lxd-client-cert is required when --lxd-url is set")?;
        let client_key = config
            .lxd_client_key
            .clone()
            .ok_or("--lxd-client-key is required when --lxd-url is set")?;
        LxdEndpoint::Https(LxdHttpsConfig {
            url,
            client_cert,
            client_key,
            server_ca: config.lxd_server_ca.clone(),
            server_cert: config.lxd_server_cert.clone(),
        })
    } else {
        LxdEndpoint::UnixSocket(config.lxd_socket.clone())
    };

    info!(socket = %config.socket.display(), "Starting OpenShell LXD compute driver");

    let lxd = LxdClient::new(endpoint)?.with_project(config.project.clone());

    // Fail fast with a clear diagnostic if the configured project does not
    // exist. This gate must run before image_alias_exists because every
    // subsequent request (including that one) is decorated with
    // project=<config.project>; a missing project would otherwise make the
    // image-alias check return a 404-driven Ok(false) and emit the wrong
    // diagnostic. Only the check itself failing (e.g. LXD not reachable yet)
    // is non-fatal here — that failure mode is already surfaced clearly
    // wherever it's next hit.
    match lxd.project_exists(&config.project).await {
        Ok(false) => {
            error!(
                project = %config.project,
                "configured LXD project does not exist; create it before starting the driver"
            );
            std::process::exit(1);
        }
        Ok(true) => {}
        Err(e) => {
            warn!(
                project = %config.project,
                %e,
                "could not verify configured LXD project exists; continuing anyway"
            );
        }
    }

    // Verify the remote LXD server supports the host architecture.
    let host_arch = openshell_driver_lxd::image::host_lxd_arch();
    if let Err(e) = lxd.verify_architecture(host_arch).await {
        error!(
            arch = %host_arch,
            %e,
            "LXD server does not support host architecture"
        );
        std::process::exit(1);
    }

    let default_image = config.default_image.clone();
    let driver = LxdComputeDriver::new(config, lxd);

    // Best-effort pre-warm of the default sandbox image. The driver pulls the
    // image from the registry on demand, so a missing local image is not an
    // error; pre-warming just makes the first create fast and surfaces an
    // invalid reference or an unreachable registry early. Any failure is
    // logged and otherwise ignored — the import is retried on first use.
    //
    // It runs in the background: a cold import takes minutes, and the socket
    // already accepts connections, so blocking here would leave a connecting
    // gateway waiting with no error until it finished. A create that arrives
    // meanwhile waits on the same import rather than starting a second one.
    let prewarm = driver.clone();
    tokio::spawn(async move {
        match prewarm.ensure_default_image().await {
            Ok(alias) => {
                info!(image = %default_image, %alias, "default sandbox image ready");
            }
            Err(e) => {
                warn!(
                    image = %default_image,
                    %e,
                    "could not pre-warm default sandbox image; it will be imported on first use"
                );
            }
        }
    });

    let service = ComputeDriverService::new(driver);

    Server::builder()
        .add_service(ComputeDriverServer::new(service))
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
            tokio::signal::ctrl_c().await.ok();
            info!("Received shutdown signal, draining in-flight requests");
        })
        .await?;

    Ok(())
}
