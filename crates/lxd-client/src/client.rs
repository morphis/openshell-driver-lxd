// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raw HTTP transport over the LXD REST API.
//!
//! Opens a fresh HTTP/1.1 connection per request, over either a Unix domain
//! socket (local LXD snap) or HTTPS+mTLS (remote LXD cluster).

use std::fmt;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;

use crate::error::LxdError;
use crate::split_image_body::SplitImageBody;
use crate::types::LxdResponse;

/// A unified raw transport stream used for WebSocket connections.
///
/// Both variants implement [`AsyncRead`] + [`AsyncWrite`] + [`Unpin`], allowing
/// `tokio_tungstenite::client_async` to work over either transport without
/// generics bubbling up into the public API.
pub(crate) enum RawStream {
    /// Local LXD daemon over a Unix domain socket.
    Unix(UnixStream),
    /// Remote LXD cluster; TLS handshake already completed.
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl RawStream {
    fn as_read(&mut self) -> Pin<&mut (dyn AsyncRead + Unpin)> {
        match self {
            RawStream::Unix(s) => Pin::new(s),
            RawStream::Tls(s) => Pin::new(s),
        }
    }

    fn as_write(&mut self) -> Pin<&mut (dyn AsyncWrite + Unpin)> {
        match self {
            RawStream::Unix(s) => Pin::new(s),
            RawStream::Tls(s) => Pin::new(s),
        }
    }
}

impl Unpin for RawStream {}

impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut().as_read().poll_read(cx, buf)
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut().as_write().poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().as_write().poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().as_write().poll_shutdown(cx)
    }
}

/// Transport endpoint for [`LxdClient`].
#[derive(Debug, Clone)]
pub enum LxdEndpoint {
    /// Local LXD daemon over a Unix domain socket.
    UnixSocket(PathBuf),
    /// Remote LXD cluster over HTTPS with mutual TLS.
    Https(LxdHttpsConfig),
}

/// Configuration for HTTPS+mTLS connections to a remote LXD cluster.
#[derive(Debug, Clone)]
pub struct LxdHttpsConfig {
    /// LXD HTTPS endpoint, e.g. `"https://10.0.0.1:8443"`.
    pub url: String,
    /// Path to the PEM-encoded client certificate for mTLS.
    pub client_cert: PathBuf,
    /// Path to the PEM-encoded client private key for mTLS.
    pub client_key: PathBuf,
    /// Path to a PEM-encoded CA certificate to verify the server cert.
    /// `None` uses the webpki CA bundle.
    pub server_ca: Option<PathBuf>,
    /// Path to the PEM-encoded certificate the server itself presents,
    /// trusted exactly and whatever names it carries, as `lxc remote add`
    /// does. LXD's self-signed certificates name only the host and loopback
    /// addresses, so this is how an LXD reached by IP address is verified.
    /// Takes precedence over `server_ca`.
    pub server_cert: Option<PathBuf>,
}

impl LxdHttpsConfig {
    /// Parses and validates `url`, requiring a host component.
    ///
    /// Called once at [`LxdClient::new`] so a malformed URL fails fast at
    /// construction rather than silently connecting to a fallback host.
    pub(crate) fn parsed_url(&self) -> Result<Uri, LxdError> {
        let uri: Uri = self.url.parse().map_err(|e| LxdError::Tls {
            reason: format!("invalid LXD URL {:?}: {e}", self.url),
        })?;
        if uri.host().is_none() {
            return Err(LxdError::Tls {
                reason: format!("LXD URL {:?} has no host", self.url),
            });
        }
        Ok(uri)
    }

    pub(crate) fn host_port(&self) -> Result<String, LxdError> {
        let uri = self.parsed_url()?;
        let host = uri.host().ok_or_else(|| LxdError::Tls {
            reason: format!("LXD URL {:?} has no host", self.url),
        })?;
        let port = uri.port_u16().unwrap_or(8443);
        if host.contains(':') {
            Ok(format!("[{host}]:{port}")) // re-bracket IPv6 for TcpStream::connect
        } else {
            Ok(format!("{host}:{port}"))
        }
    }

    fn hostname(&self) -> Result<String, LxdError> {
        // Uri::host() strips IPv6 brackets automatically
        let uri = self.parsed_url()?;
        let host = uri.host().ok_or_else(|| LxdError::Tls {
            reason: format!("LXD URL {:?} has no host", self.url),
        })?;
        Ok(host.to_string())
    }

    pub(crate) fn server_name(&self) -> Result<rustls::pki_types::ServerName<'static>, LxdError> {
        rustls::pki_types::ServerName::try_from(self.hostname()?).map_err(|e| LxdError::Tls {
            reason: format!("invalid server name: {e}"),
        })
    }

    pub(crate) fn build_connector(&self) -> Result<tokio_rustls::TlsConnector, LxdError> {
        use std::fs::File;
        use std::io::BufReader;
        use std::sync::Arc;

        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls_pemfile::{certs, private_key};

        let cert_file = File::open(&self.client_cert).map_err(|e| LxdError::Tls {
            reason: format!("cannot open client cert: {e}"),
        })?;
        let client_certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(cert_file))
            .collect::<Result<_, _>>()
            .map_err(|e| LxdError::Tls {
                reason: format!("invalid client cert PEM: {e}"),
            })?;

        let key_file = File::open(&self.client_key).map_err(|e| LxdError::Tls {
            reason: format!("cannot open client key: {e}"),
        })?;
        let key: PrivateKeyDer<'static> = private_key(&mut BufReader::new(key_file))
            .map_err(|e| LxdError::Tls {
                reason: format!("invalid client key PEM: {e}"),
            })?
            .ok_or_else(|| LxdError::Tls {
                reason: "no private key in PEM file".into(),
            })?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| LxdError::Tls {
                reason: format!("TLS protocol error: {e}"),
            })?;

        if let Some(cert_path) = &self.server_cert {
            let cert_file = File::open(cert_path).map_err(|e| LxdError::Tls {
                reason: format!("cannot open server cert: {e}"),
            })?;
            let mut server_certs: Vec<CertificateDer<'static>> =
                certs(&mut BufReader::new(cert_file))
                    .collect::<Result<_, _>>()
                    .map_err(|e| LxdError::Tls {
                        reason: format!("invalid server cert PEM: {e}"),
                    })?;
            if server_certs.len() != 1 {
                return Err(LxdError::Tls {
                    reason: format!(
                        "server cert file must hold exactly one certificate, found {}",
                        server_certs.len()
                    ),
                });
            }
            let verifier = PinnedServerCert {
                cert: server_certs.remove(0),
                provider,
            };
            let tls_config = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(client_certs, key)
                .map_err(|e| LxdError::Tls {
                    reason: format!("TLS cert error: {e}"),
                })?;
            return Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_config)));
        }

        let root_store = if let Some(ca_path) = &self.server_ca {
            let ca_file = File::open(ca_path).map_err(|e| LxdError::Tls {
                reason: format!("cannot open server CA: {e}"),
            })?;
            let ca_certs: Vec<CertificateDer<'static>> = certs(&mut BufReader::new(ca_file))
                .collect::<Result<_, _>>()
                .map_err(|e| LxdError::Tls {
                    reason: format!("invalid server CA PEM: {e}"),
                })?;
            let mut store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                store.add(cert).map_err(|e| LxdError::Tls {
                    reason: format!("invalid CA cert: {e}"),
                })?;
            }
            store
        } else {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            store
        };

        let tls_config = builder
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, key)
            .map_err(|e| LxdError::Tls {
                reason: format!("TLS cert error: {e}"),
            })?;

        Ok(tokio_rustls::TlsConnector::from(Arc::new(tls_config)))
    }
}

/// Trusts exactly one server certificate, whatever names it carries.
///
/// The handshake signature is still checked against that certificate's key,
/// so only a server holding its private key gets through. Names and validity
/// dates are not checked — the certificate is identified by its bytes, as
/// `lxc` does for the remotes it trusts.
#[derive(Debug)]
struct PinnedServerCert {
    cert: rustls::pki_types::CertificateDer<'static>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Default LXD project. LXD always has a `default` project.
pub const DEFAULT_PROJECT: &str = "default";

/// Async client for the LXD REST API.
///
/// Opens a fresh connection per request. Use [`LxdEndpoint::UnixSocket`] for a
/// local LXD snap installation, or [`LxdEndpoint::Https`] for a remote LXD
/// cluster over HTTPS+mTLS.
#[derive(Clone)]
pub struct LxdClient {
    endpoint: LxdEndpoint,
    /// Pre-built TLS connector, cached at construction to avoid re-reading cert
    /// files on every request.
    tls_connector: Option<tokio_rustls::TlsConnector>,
    /// Target LXD project applied to every request as a `project` query
    /// parameter. Defaults to `"default"`.
    project: String,
}

impl LxdClient {
    /// Creates a client for the given [`LxdEndpoint`].
    ///
    /// For [`LxdEndpoint::UnixSocket`] this is infallible in practice.
    /// For [`LxdEndpoint::Https`] this validates the URL and reads cert files
    /// from disk once to build the [`tokio_rustls::TlsConnector`]; subsequent
    /// requests reuse it.
    pub fn new(endpoint: LxdEndpoint) -> Result<Self, LxdError> {
        let tls_connector = match &endpoint {
            LxdEndpoint::UnixSocket(_) => None,
            LxdEndpoint::Https(config) => {
                config.parsed_url()?;
                Some(config.build_connector()?)
            }
        };
        Ok(Self {
            endpoint,
            tls_connector,
            project: DEFAULT_PROJECT.to_string(),
        })
    }

    /// Sets the target LXD project for every request.
    ///
    /// Consumes `self` and returns it, so existing call sites that use
    /// `LxdClient::new(endpoint)?` unchanged keep the `"default"` project.
    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = project.into();
        self
    }

    /// Appends `project=<name>` to `path`, URL-encoding the project name.
    ///
    /// Uses `?` when the path has no query string and `&` when it already has
    /// one. This is the single choke point for project scoping on the wire.
    pub(crate) fn decorate_path(&self, path: &str) -> String {
        let base = url::Url::parse("http://localhost").expect("valid base URL");
        let mut url = base.join(path).expect("valid relative path");
        url.query_pairs_mut().append_pair("project", &self.project);
        match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_string(),
        }
    }

    /// WebSocket scheme for the configured endpoint (`"ws"` or `"wss"`).
    pub(crate) fn ws_scheme(&self) -> &'static str {
        match &self.endpoint {
            LxdEndpoint::UnixSocket(_) => "ws",
            LxdEndpoint::Https(_) => "wss",
        }
    }

    /// Opens a raw transport connection without layering HTTP on top.
    ///
    /// Used by [`crate::events`] to hand a connected stream to
    /// `tokio_tungstenite::client_async` for the WebSocket upgrade.
    pub(crate) async fn connect_raw(&self) -> Result<(RawStream, String), LxdError> {
        match &self.endpoint {
            LxdEndpoint::UnixSocket(socket_path) => {
                let stream = UnixStream::connect(socket_path).await?;
                Ok((RawStream::Unix(stream), "localhost".to_string()))
            }
            LxdEndpoint::Https(config) => {
                use tokio::net::TcpStream;
                let connector = self.tls_connector.as_ref().ok_or_else(|| LxdError::Tls {
                    reason: "internal error: no TLS connector for Https endpoint".to_string(),
                })?;
                let host = config.host_port()?;
                let tcp = TcpStream::connect(&host).await?;
                let server_name = config.server_name()?;
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(LxdError::Io)?;
                Ok((RawStream::Tls(Box::new(tls)), host))
            }
        }
    }

    /// Opens a fresh connection and returns an HTTP/1.1 sender plus the value
    /// to use for the `Host` header.
    async fn connect<B>(
        &self,
    ) -> Result<(hyper::client::conn::http1::SendRequest<B>, String), LxdError>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let (raw, host) = self.connect_raw().await?;
        let sender = do_handshake(TokioIo::new(raw)).await?;
        Ok((sender, host))
    }

    /// Sends a request and deserializes the LXD response envelope's
    /// `metadata` as `T`.
    ///
    /// Returns [`LxdError::Api`] for non-2xx responses or an `error`-typed
    /// envelope.
    pub(crate) async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<LxdResponse<T>, LxdError> {
        let (mut sender, host) = self.connect().await?;

        let body_bytes = match &body {
            Some(value) => serde_json::to_vec(value)?,
            None => Vec::new(),
        };

        let decorated_path = self.decorate_path(path);
        let mut builder = Request::builder()
            .method(method)
            .uri(&decorated_path)
            .header("Host", host);
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        let request = builder.body(Full::new(Bytes::from(body_bytes)))?;

        let response = sender.send_request(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();

        // Check HTTP status first so a non-JSON body (e.g. a proxy 502) surfaces
        // as LxdError::Api with the real HTTP code rather than LxdError::Json.
        if !status.is_success() {
            let (status_code, message) =
                serde_json::from_slice::<LxdResponse<serde_json::Value>>(&body)
                    .ok()
                    .filter(|r| r.type_ == "error")
                    .map(|r| {
                        let msg = r.error.unwrap_or_else(|| format!("HTTP {status}"));
                        // LXD's error envelope puts the real code in `error_code`.
                        (r.error_code, msg)
                    })
                    .unwrap_or_else(|| (status.as_u16(), format!("HTTP {status}")));
            return Err(LxdError::Api {
                status_code,
                message,
            });
        }

        let parsed: LxdResponse<T> = serde_json::from_slice(&body)?;

        // LXD can return type="error" with 200 OK in edge cases.
        if parsed.type_ == "error" {
            let message = parsed
                .error
                .clone()
                .unwrap_or_else(|| format!("LXD error {}", parsed.error_code));
            return Err(LxdError::Api {
                status_code: parsed.error_code,
                message,
            });
        }

        Ok(parsed)
    }

    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<LxdResponse<T>, LxdError> {
        self.request(Method::GET, path, None).await
    }

    pub(crate) async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
    ) -> Result<LxdResponse<T>, LxdError> {
        self.request(Method::POST, path, Some(body)).await
    }

    pub(crate) async fn put<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
    ) -> Result<LxdResponse<T>, LxdError> {
        self.request(Method::PUT, path, Some(body)).await
    }

    pub(crate) async fn patch<T: DeserializeOwned>(
        &self,
        path: &str,
        body: Value,
    ) -> Result<LxdResponse<T>, LxdError> {
        self.request(Method::PATCH, path, Some(body)).await
    }

    /// Queries the LXD server's supported architectures (`GET /1.0`).
    pub async fn server_architectures(&self) -> Result<Vec<String>, LxdError> {
        let response = self.get::<Value>("/1.0").await?;
        let metadata = response.into_metadata()?;
        let archs = metadata
            .get("environment")
            .and_then(|e| e.get("architectures"))
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(archs)
    }

    /// Verifies that the LXD server supports the requested architecture.
    pub async fn verify_architecture(&self, expected_arch: &str) -> Result<(), LxdError> {
        let archs = self.server_architectures().await?;
        if archs.is_empty() {
            return Ok(());
        }
        if !archs.iter().any(|a| a == expected_arch) {
            return Err(LxdError::Api {
                status_code: 400,
                message: format!(
                    "LXD server does not support architecture '{expected_arch}'; supported architectures: {:?}",
                    archs
                ),
            });
        }
        Ok(())
    }

    pub(crate) async fn delete<T: DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<LxdResponse<T>, LxdError> {
        self.request(Method::DELETE, path, None).await
    }

    /// POST raw bytes with arbitrary extra headers and return the deserialized response.
    ///
    /// Used for endpoints like image imports where the request payload is multipart/form-data
    /// or binary data, but the response is LXD's standard JSON envelope.
    pub(crate) async fn post_raw_response<T: DeserializeOwned>(
        &self,
        path: &str,
        content_type: &str,
        extra_headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<LxdResponse<T>, LxdError> {
        let (mut sender, host) = self.connect().await?;

        let decorated_path = self.decorate_path(path);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&decorated_path)
            .header("Host", host)
            .header("Content-Type", content_type);
        for (name, value) in extra_headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(Full::new(body))?;

        let response = sender.send_request(request).await?;
        let status = response.status();
        let resp_body = response.into_body().collect().await?.to_bytes();

        if !status.is_success() {
            let (status_code, message) = serde_json::from_slice::<LxdResponse<Value>>(&resp_body)
                .ok()
                .filter(|r| r.type_ == "error")
                .map(|r| {
                    let msg = r.error.unwrap_or_else(|| format!("HTTP {status}"));
                    (r.error_code, msg)
                })
                .unwrap_or_else(|| (status.as_u16(), format!("HTTP {status}")));
            return Err(LxdError::Api {
                status_code,
                message,
            });
        }

        let parsed: LxdResponse<T> = serde_json::from_slice(&resp_body)?;

        if parsed.type_ == "error" {
            let message = parsed
                .error
                .clone()
                .unwrap_or_else(|| format!("LXD error {}", parsed.error_code));
            return Err(LxdError::Api {
                status_code: parsed.error_code,
                message,
            });
        }

        Ok(parsed)
    }

    /// POST a streaming body with arbitrary content-type and return the deserialized response.
    ///
    /// Used for split image imports where the request payload streams a multi-gigabyte rootfs
    /// file in bounded chunks, while the response is LXD's standard JSON envelope.
    pub(crate) async fn post_streaming_response<T: DeserializeOwned>(
        &self,
        path: &str,
        content_type: &str,
        body: SplitImageBody,
    ) -> Result<LxdResponse<T>, LxdError> {
        let (mut sender, host) = self.connect::<SplitImageBody>().await?;

        let decorated_path = self.decorate_path(path);
        let request = Request::builder()
            .method(Method::POST)
            .uri(&decorated_path)
            .header("Host", host)
            .header("Content-Type", content_type)
            .body(body)?;

        let response = sender.send_request(request).await?;
        let status = response.status();
        let resp_body = response.into_body().collect().await?.to_bytes();

        if !status.is_success() {
            let (status_code, message) = serde_json::from_slice::<LxdResponse<Value>>(&resp_body)
                .ok()
                .filter(|r| r.type_ == "error")
                .map(|r| {
                    let msg = r.error.unwrap_or_else(|| format!("HTTP {status}"));
                    (r.error_code, msg)
                })
                .unwrap_or_else(|| (status.as_u16(), format!("HTTP {status}")));
            return Err(LxdError::Api {
                status_code,
                message,
            });
        }

        let parsed: LxdResponse<T> = serde_json::from_slice(&resp_body)?;

        if parsed.type_ == "error" {
            let message = parsed
                .error
                .clone()
                .unwrap_or_else(|| format!("LXD error {}", parsed.error_code));
            return Err(LxdError::Api {
                status_code: parsed.error_code,
                message,
            });
        }

        Ok(parsed)
    }

    /// POST raw bytes with arbitrary extra headers.
    ///
    /// Used for the file-push endpoint whose sync response has `metadata: null`
    /// and therefore cannot go through the generic `request::<T>` path.
    pub(crate) async fn post_raw(
        &self,
        path: &str,
        content_type: &str,
        extra_headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<(), LxdError> {
        let (mut sender, host) = self.connect().await?;

        let decorated_path = self.decorate_path(path);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&decorated_path)
            .header("Host", host)
            .header("Content-Type", content_type);
        for (name, value) in extra_headers {
            builder = builder.header(*name, *value);
        }
        let request = builder.body(Full::new(body))?;

        let response = sender.send_request(request).await?;
        let status = response.status();
        let resp_body = response.into_body().collect().await?.to_bytes();

        // Mirrors `request()`'s error handling: prefer the real code/message
        // from LXD's envelope when present, falling back to the raw HTTP
        // status for a non-JSON body (e.g. a proxy error page).
        if !status.is_success() {
            let (status_code, message) = serde_json::from_slice::<LxdResponse<Value>>(&resp_body)
                .ok()
                .filter(|r| r.type_ == "error")
                .map(|r| {
                    let msg = r.error.unwrap_or_else(|| format!("HTTP {status}"));
                    (r.error_code, msg)
                })
                .unwrap_or_else(|| (status.as_u16(), format!("HTTP {status}")));
            return Err(LxdError::Api {
                status_code,
                message,
            });
        }

        // LXD can return type="error" with 200 OK in edge cases; tolerate a
        // body that isn't the LXD envelope shape rather than treating it as
        // an error, since post_raw is also used for non-JSON-envelope bodies.
        if !resp_body.is_empty() {
            if let Ok(parsed) = serde_json::from_slice::<LxdResponse<Value>>(&resp_body) {
                if parsed.type_ == "error" {
                    let message = parsed
                        .error
                        .unwrap_or_else(|| format!("LXD error {}", parsed.error_code));
                    return Err(LxdError::Api {
                        status_code: parsed.error_code,
                        message,
                    });
                }
            }
        }
        Ok(())
    }

    /// GET raw bytes with response headers.
    pub(crate) async fn get_raw_with_headers(
        &self,
        path: &str,
    ) -> Result<(hyper::HeaderMap, Bytes), LxdError> {
        let (mut sender, host) = self.connect().await?;

        let decorated_path = self.decorate_path(path);
        let request = Request::builder()
            .method(Method::GET)
            .uri(&decorated_path)
            .header("Host", host)
            .body(Full::new(Bytes::new()))?;

        let response = sender.send_request(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await?.to_bytes();

        if !status.is_success() {
            let (status_code, message) = serde_json::from_slice::<LxdResponse<Value>>(&body)
                .ok()
                .filter(|r| r.type_ == "error")
                .map(|r| {
                    let msg = r.error.unwrap_or_else(|| format!("HTTP {status}"));
                    (r.error_code, msg)
                })
                .unwrap_or_else(|| (status.as_u16(), format!("HTTP {status}")));
            return Err(LxdError::Api {
                status_code,
                message,
            });
        }

        Ok((headers, body))
    }
}

impl fmt::Debug for LxdClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LxdClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

async fn do_handshake<IO, B>(io: IO) -> Result<hyper::client::conn::http1::SendRequest<B>, LxdError>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!(%err, "lxd-client: connection closed with error");
        }
    });
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_server_cert_accepts_only_its_own_bytes() {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

        let pinned = PinnedServerCert {
            cert: CertificateDer::from(vec![1, 2, 3, 4]),
            provider: std::sync::Arc::new(rustls::crypto::ring::default_provider()),
        };
        // The name is ignored: LXD's certificate names the host, while the
        // driver may dial it by address.
        let name = ServerName::try_from("192.168.1.166").unwrap();

        assert!(pinned
            .verify_server_cert(
                &CertificateDer::from(vec![1, 2, 3, 4]),
                &[],
                &name,
                &[],
                UnixTime::now()
            )
            .is_ok());
        assert!(pinned
            .verify_server_cert(
                &CertificateDer::from(vec![1, 2, 3, 5]),
                &[],
                &name,
                &[],
                UnixTime::now()
            )
            .is_err());
        assert!(!pinned.supported_verify_schemes().is_empty());
    }

    fn test_client() -> LxdClient {
        LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from("/tmp/test.sock"))).unwrap()
    }

    #[test]
    fn decorate_path_bare_path_uses_question_mark() {
        let client = test_client().with_project("p");
        assert_eq!(
            client.decorate_path("/1.0/instances"),
            "/1.0/instances?project=p"
        );
    }

    #[test]
    fn decorate_path_with_recursion_uses_ampersand() {
        let client = test_client().with_project("p");
        assert_eq!(
            client.decorate_path("/1.0/instances?recursion=1"),
            "/1.0/instances?recursion=1&project=p"
        );
    }

    #[test]
    fn decorate_path_with_file_push_path_uses_ampersand() {
        let client = test_client().with_project("p");
        assert_eq!(
            client.decorate_path("/1.0/instances/foo/files?path=/etc/test"),
            "/1.0/instances/foo/files?path=/etc/test&project=p"
        );
    }

    #[test]
    fn decorate_path_wait_timeout_uses_ampersand() {
        let client = test_client().with_project("p");
        assert_eq!(
            client.decorate_path("/1.0/operations/uuid/wait?timeout=-1"),
            "/1.0/operations/uuid/wait?timeout=-1&project=p"
        );
    }

    #[test]
    fn decorate_path_url_encodes_project_name() {
        let client = test_client().with_project("my project");
        assert_eq!(
            client.decorate_path("/1.0/instances"),
            "/1.0/instances?project=my+project"
        );
    }

    #[test]
    fn with_project_overrides_default() {
        let client = test_client().with_project("custom");
        assert_eq!(client.project, "custom");
    }

    #[test]
    fn new_defaults_to_default_project() {
        let client = test_client();
        assert_eq!(client.project, DEFAULT_PROJECT);
    }
}
