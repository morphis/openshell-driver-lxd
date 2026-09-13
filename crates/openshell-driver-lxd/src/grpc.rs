// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ComputeDriverService` — thin tonic trait implementation that delegates
//! to [`LxdComputeDriver`] and maps [`DriverError`] to [`Status`].

use std::pin::Pin;

use computev1::pb::compute_driver_server::ComputeDriver;
use computev1::pb::DriverSandbox;
use computev1::pb::{
    watch_sandboxes_event, CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest,
    DeleteSandboxResponse, DeleteWorkspaceRequest, DeleteWorkspaceResponse, EnsureWorkspaceRequest,
    EnsureWorkspaceResponse, GetCapabilitiesRequest, GetCapabilitiesResponse,
    GetGatewayListenerRequirementsRequest, GetGatewayListenerRequirementsResponse,
    GetSandboxRequest, GetSandboxResponse, ListSandboxesRequest, ListSandboxesResponse,
    StartSandboxRequest, StartSandboxResponse, StopSandboxRequest, StopSandboxResponse,
    ValidateSandboxCreateRequest, ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent,
    WatchSandboxesEvent, WatchSandboxesRequest, WatchSandboxesSandboxEvent,
};
use futures::Stream;
use tokio::sync::broadcast;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tokio_stream::StreamExt;
use tonic::{Code, Request, Response, Status};

use crate::driver::LxdComputeDriver;
use crate::error::DriverError;
use crate::watcher;

#[derive(Debug, Clone, PartialEq)]
pub enum WatchEvent {
    Sandbox(Box<DriverSandbox>),
    Deleted(String),
}

#[derive(Debug, Clone)]
pub struct ComputeDriverService {
    driver: LxdComputeDriver,
    /// Ordered event stream published on state changes and deletions, so
    /// WatchSandboxes preserves the relative order of lifecycle events
    /// (e.g. an exit snapshot is never delivered after a deletion).
    pub(crate) event_tx: broadcast::Sender<WatchEvent>,
}

impl ComputeDriverService {
    #[must_use]
    pub fn new(driver: LxdComputeDriver) -> Self {
        let (event_tx, _) = broadcast::channel(64);
        watcher::spawn(driver.lxd_client(), event_tx.clone());
        Self { driver, event_tx }
    }

    /// Builds the service without the LXD lifecycle watcher, for tests that
    /// have no LXD to subscribe to.
    #[must_use]
    pub fn without_watcher(driver: LxdComputeDriver) -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self { driver, event_tx }
    }
}

/// Resolves the instance name a request should act on. Prefers
/// `sandbox_name` (the common case); when it's empty, falls back to
/// looking up the instance whose `user.openshell.sandbox_id` config key
/// matches `sandbox_id` — both fields exist on these requests precisely so
/// callers can address a sandbox by either.
async fn resolve_name(
    driver: &LxdComputeDriver,
    sandbox_name: &str,
    sandbox_id: &str,
) -> Result<String, Status> {
    if !sandbox_name.is_empty() {
        return Ok(sandbox_name.to_string());
    }
    if sandbox_id.is_empty() {
        return Err(DriverError::InvalidArgument(
            "sandbox_name or sandbox_id is required".to_string(),
        )
        .into());
    }
    driver
        .find_name_by_sandbox_id(sandbox_id)
        .await?
        .ok_or_else(|| {
            Status::not_found(format!("no sandbox found with sandbox_id {sandbox_id:?}"))
        })
}

#[tonic::async_trait]
impl ComputeDriver for ComputeDriverService {
    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(self.driver.capabilities()))
    }

    /// Asks the gateway for a sandbox-callback listener when one is
    /// configured (`--gateway-callback-listener`); otherwise sandboxes use the
    /// gateway's main listener and nothing extra is needed.
    ///
    /// Answering rather than leaving the RPC unimplemented matters: the
    /// gateway calls it at startup and aborts on any error other than
    /// `Unimplemented`.
    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements: self.driver.gateway_listener_requirements(),
        }))
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let req = request.into_inner();
        let name = resolve_name(&self.driver, &req.sandbox_name, &req.sandbox_id).await?;
        self.driver.start_sandbox(&name).await?;
        Ok(Response::new(StartSandboxResponse {}))
    }

    /// Workspaces own no LXD resources of their own: every sandbox lives in
    /// the driver's single project, so there is nothing to provision.
    async fn ensure_workspace(
        &self,
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Ok(Response::new(EnsureWorkspaceResponse {}))
    }

    /// See [`Self::ensure_workspace`]: there is nothing to tear down.
    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Ok(Response::new(DeleteWorkspaceResponse {}))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request.into_inner().sandbox.ok_or_else(|| {
            Status::from(DriverError::InvalidArgument(
                "sandbox is required".to_string(),
            ))
        })?;
        self.driver.validate_sandbox_create(&sandbox).await?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let req = request.into_inner();
        let name = resolve_name(&self.driver, &req.sandbox_name, &req.sandbox_id).await?;
        let sandbox = self.driver.get_sandbox(&name).await?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let sandboxes = self.driver.list_sandboxes().await?;
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request.into_inner().sandbox.ok_or_else(|| {
            Status::from(DriverError::InvalidArgument(
                "sandbox is required".to_string(),
            ))
        })?;
        self.driver.create_sandbox(&sandbox).await?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let req = request.into_inner();
        let name = resolve_name(&self.driver, &req.sandbox_name, &req.sandbox_id).await?;
        self.driver.stop_sandbox(&name).await?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let req = request.into_inner();
        let name = match resolve_name(&self.driver, &req.sandbox_name, &req.sandbox_id).await {
            Ok(name) => name,
            // No instance carries this id, so there is nothing to delete —
            // the same answer an unknown name gets. Delete must be idempotent
            // however the caller addresses the sandbox.
            Err(status) if status.code() == Code::NotFound => {
                return Ok(Response::new(DeleteSandboxResponse { deleted: false }));
            }
            Err(status) => return Err(status),
        };
        match self.driver.delete_sandbox(&name).await? {
            Some(sandbox_id) => {
                if !sandbox_id.is_empty() {
                    self.event_tx.send(WatchEvent::Deleted(sandbox_id)).ok();
                }
                Ok(Response::new(DeleteSandboxResponse { deleted: true }))
            }
            None => Ok(Response::new(DeleteSandboxResponse { deleted: false })),
        }
    }

    type WatchSandboxesStream =
        Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send>>;

    /// Streams the current state of every sandbox, then every change.
    ///
    /// The snapshot of existing sandboxes matters whenever a watcher
    /// (re)connects: without it, anything that changed while it was not
    /// connected — a driver restart, a gateway reconnect — would only be
    /// noticed on the gateway's next reconcile.
    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let lagged = |n| {
            Status::data_loss(format!(
                "WatchSandboxes receiver lagged and missed {n} event(s); reconnect and re-list to resync"
            ))
        };

        let live_events =
            BroadcastStream::new(self.event_tx.subscribe()).map(move |result| match result {
                Ok(WatchEvent::Sandbox(sandbox)) => Ok(WatchSandboxesEvent {
                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                        WatchSandboxesSandboxEvent {
                            sandbox: Some(*sandbox),
                        },
                    )),
                }),
                Ok(WatchEvent::Deleted(sandbox_id)) => Ok(WatchSandboxesEvent {
                    payload: Some(watch_sandboxes_event::Payload::Deleted(
                        WatchSandboxesDeletedEvent { sandbox_id },
                    )),
                }),
                Err(BroadcastStreamRecvError::Lagged(n)) => Err(lagged(n)),
            });

        // Subscribed above, before listing: a change that lands while the
        // list is being read is still delivered, after the snapshot. Every
        // LXD state change publishes its own event, so the last snapshot a
        // watcher receives for a sandbox is always its latest state.
        let current = self
            .driver
            .list_sandboxes()
            .await?
            .into_iter()
            .map(|sandbox| {
                Ok(WatchSandboxesEvent {
                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                        WatchSandboxesSandboxEvent {
                            sandbox: Some(sandbox),
                        },
                    )),
                })
            });

        Ok(Response::new(Box::pin(
            tokio_stream::iter(current).chain(live_events),
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use clap::Parser;
    use lxd_client::{Instance, LxdClient, LxdEndpoint};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    use super::*;
    use crate::config::Config;
    use crate::mapping;

    /// A service whose LXD client points at `lxd_socket`.
    fn service_on(lxd_socket: &Path) -> ComputeDriverService {
        let config = Config::parse_from(["openshell-driver-lxd"]);
        let lxd = LxdClient::new(LxdEndpoint::UnixSocket(lxd_socket.to_path_buf())).unwrap();
        ComputeDriverService::without_watcher(LxdComputeDriver::new(config, lxd))
    }

    /// A service for paths that never reach LXD: the client only connects
    /// when a request is sent, and its socket does not exist.
    fn service() -> ComputeDriverService {
        service_on(Path::new("/nonexistent/lxd.socket"))
    }

    /// Stands in for LXD on a Unix socket, answering every request with
    /// `instances` as the response metadata — enough for ListSandboxes.
    fn fake_lxd(instances: Vec<Instance>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("lxd.socket");
        let listener = UnixListener::bind(&socket).unwrap();
        let body = serde_json::json!({
            "type": "sync",
            "status": "Success",
            "status_code": 200,
            "error_code": 0,
            "error": "",
            "metadata": instances,
        })
        .to_string();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    // Requests here carry no body: read up to the blank line.
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match conn.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = conn.write_all(response.as_bytes()).await;
                });
            }
        });
        (dir, socket)
    }

    fn instance(name: &str, status: &str, config: &[(&str, &str)]) -> Instance {
        Instance {
            name: name.to_string(),
            description: String::new(),
            status: status.to_string(),
            status_code: 0,
            architecture: "x86_64".to_string(),
            ephemeral: false,
            profiles: vec!["default".to_string()],
            config: config
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            devices: HashMap::new(),
            type_: "container".to_string(),
            project: "default".to_string(),
        }
    }

    /// A watch on a service backed by a fake LXD with no instances, so the
    /// stream starts with nothing but live events.
    async fn empty_watch() -> (
        ComputeDriverService,
        <ComputeDriverService as ComputeDriver>::WatchSandboxesStream,
        tempfile::TempDir,
    ) {
        let (dir, socket) = fake_lxd(Vec::new());
        let service = service_on(&socket);
        let stream = service
            .watch_sandboxes(Request::new(WatchSandboxesRequest {}))
            .await
            .expect("watch should open")
            .into_inner();
        (service, stream, dir)
    }

    async fn next_event(
        stream: &mut <ComputeDriverService as ComputeDriver>::WatchSandboxesStream,
    ) -> Result<WatchSandboxesEvent, Status> {
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("watch stream should yield within 5s")
            .expect("watch stream should not end")
    }

    /// The gateway calls this at startup and aborts on any error but
    /// `Unimplemented`; without a callback listener the driver needs none.
    #[tokio::test]
    async fn gateway_listener_requirements_are_empty_by_default() {
        let response = service()
            .get_gateway_listener_requirements(Request::new(
                GetGatewayListenerRequirementsRequest {},
            ))
            .await
            .expect("listener requirements should be answered")
            .into_inner();
        assert!(response.requirements.is_empty());
    }

    #[tokio::test]
    async fn gateway_listener_requirements_carry_the_callback_listener() {
        use computev1::pb::gateway_listener_requirement::Selector;

        let config = Config::parse_from([
            "openshell-driver-lxd",
            "--gateway-callback-listener",
            "169.254.17.1:17670",
        ]);
        let lxd =
            LxdClient::new(LxdEndpoint::UnixSocket("/nonexistent/lxd.socket".into())).unwrap();
        let response = ComputeDriverService::without_watcher(LxdComputeDriver::new(config, lxd))
            .get_gateway_listener_requirements(Request::new(
                GetGatewayListenerRequirementsRequest {},
            ))
            .await
            .expect("listener requirements should be answered")
            .into_inner();

        assert_eq!(response.requirements.len(), 1);
        assert_eq!(
            response.requirements[0].selector,
            Some(Selector::ExactBindAddress("169.254.17.1:17670".to_string()))
        );
        assert!(!response.requirements[0].reason.is_empty());
    }

    #[tokio::test]
    async fn workspaces_need_no_provisioning() {
        let service = service();
        service
            .ensure_workspace(Request::new(EnsureWorkspaceRequest {
                workspace: "ws".to_string(),
            }))
            .await
            .expect("ensure_workspace succeeds");
        service
            .delete_workspace(Request::new(DeleteWorkspaceRequest {
                workspace: "ws".to_string(),
            }))
            .await
            .expect("delete_workspace succeeds");
    }

    #[tokio::test]
    async fn resolve_name_prefers_name_without_looking_up_id() {
        let service = service();
        let name = resolve_name(&service.driver, "by-name", "some-id")
            .await
            .expect("a name needs no lookup");
        assert_eq!(name, "by-name");
    }

    #[tokio::test]
    async fn resolve_name_requires_name_or_id() {
        let service = service();
        let status = resolve_name(&service.driver, "", "")
            .await
            .expect_err("neither name nor id should be rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn requests_without_a_sandbox_are_invalid() {
        let service = service();

        let status = service
            .validate_sandbox_create(Request::new(ValidateSandboxCreateRequest { sandbox: None }))
            .await
            .expect_err("validate without sandbox should fail");
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .create_sandbox(Request::new(CreateSandboxRequest { sandbox: None }))
            .await
            .expect_err("create without sandbox should fail");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn stop_and_delete_require_name_or_id() {
        let service = service();

        let status = service
            .stop_sandbox(Request::new(StopSandboxRequest::default()))
            .await
            .expect_err("stop without identity should fail");
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .delete_sandbox(Request::new(DeleteSandboxRequest::default()))
            .await
            .expect_err("delete without identity should fail");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn watch_forwards_deletions_and_snapshots() {
        let (service, mut stream, _lxd) = empty_watch().await;

        service
            .event_tx
            .send(WatchEvent::Deleted("sb-gone".to_string()))
            .unwrap();
        match next_event(&mut stream).await.unwrap().payload {
            Some(watch_sandboxes_event::Payload::Deleted(deleted)) => {
                assert_eq!(deleted.sandbox_id, "sb-gone");
            }
            other => panic!("expected a Deleted event, got {other:?}"),
        }

        let snapshot = DriverSandbox {
            id: "sb-live".to_string(),
            name: "sb-live".to_string(),
            ..Default::default()
        };
        service
            .event_tx
            .send(WatchEvent::Sandbox(Box::new(snapshot.clone())))
            .unwrap();
        match next_event(&mut stream).await.unwrap().payload {
            Some(watch_sandboxes_event::Payload::Sandbox(event)) => {
                assert_eq!(event.sandbox, Some(snapshot));
            }
            other => panic!("expected a Sandbox event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watch_preserves_event_order_across_types() {
        let (service, mut stream, _lxd) = empty_watch().await;

        let snapshot = DriverSandbox {
            id: "sb-live".to_string(),
            name: "sb-live".to_string(),
            ..Default::default()
        };
        service
            .event_tx
            .send(WatchEvent::Sandbox(Box::new(snapshot.clone())))
            .unwrap();
        service
            .event_tx
            .send(WatchEvent::Deleted("sb-live".to_string()))
            .unwrap();

        match next_event(&mut stream).await.unwrap().payload {
            Some(watch_sandboxes_event::Payload::Sandbox(event)) => {
                assert_eq!(event.sandbox, Some(snapshot));
            }
            other => panic!("expected a Sandbox event, got {other:?}"),
        }
        match next_event(&mut stream).await.unwrap().payload {
            Some(watch_sandboxes_event::Payload::Deleted(deleted)) => {
                assert_eq!(deleted.sandbox_id, "sb-live");
            }
            other => panic!("expected a Deleted event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn every_watcher_receives_every_event() {
        let (service, mut first, _lxd) = empty_watch().await;
        let mut second = service
            .watch_sandboxes(Request::new(WatchSandboxesRequest {}))
            .await
            .unwrap()
            .into_inner();

        service
            .event_tx
            .send(WatchEvent::Deleted("sb-1".to_string()))
            .unwrap();

        for stream in [&mut first, &mut second] {
            assert!(matches!(
                next_event(stream).await.unwrap().payload,
                Some(watch_sandboxes_event::Payload::Deleted(_))
            ));
        }
    }

    /// A watcher that falls behind must be told it missed events (so the
    /// gateway reconnects and re-lists) rather than silently skipping them.
    #[tokio::test]
    async fn lagging_watcher_gets_data_loss() {
        let (service, mut stream, _lxd) = empty_watch().await;

        for i in 0..100 {
            service
                .event_tx
                .send(WatchEvent::Deleted(format!("sb-{i}")))
                .unwrap();
        }

        let status = next_event(&mut stream)
            .await
            .expect_err("an overflowed receiver should report the gap");
        assert_eq!(status.code(), Code::DataLoss);
    }

    /// A new watcher first receives the current state of every managed
    /// sandbox, then live events.
    #[tokio::test]
    async fn watch_starts_with_a_snapshot_of_every_managed_sandbox() {
        let (_lxd, socket) = fake_lxd(vec![
            instance(
                "sb-running",
                "Running",
                &[(mapping::KEY_SANDBOX_ID, "id-running")],
            ),
            instance(
                "sb-exited",
                "Stopped",
                &[
                    (mapping::KEY_SANDBOX_ID, "id-exited"),
                    ("volatile.last_state.power", "STOPPED"),
                ],
            ),
            instance("not-a-sandbox", "Running", &[]),
        ]);
        let service = service_on(&socket);
        let mut stream = service
            .watch_sandboxes(Request::new(WatchSandboxesRequest {}))
            .await
            .expect("watch should open")
            .into_inner();

        let mut snapshots = HashMap::new();
        for _ in 0..2 {
            match next_event(&mut stream).await.unwrap().payload {
                Some(watch_sandboxes_event::Payload::Sandbox(event)) => {
                    let sandbox = event.sandbox.unwrap();
                    let reason = sandbox.status.unwrap().conditions[0].reason.clone();
                    snapshots.insert(sandbox.id, reason);
                }
                other => panic!("expected a snapshot, got {other:?}"),
            }
        }
        assert_eq!(
            snapshots,
            HashMap::from([
                ("id-running".to_string(), String::new()),
                ("id-exited".to_string(), "ContainerExited".to_string()),
            ])
        );

        // Then live events, and nothing about the unmanaged instance.
        service
            .event_tx
            .send(WatchEvent::Deleted("id-exited".to_string()))
            .unwrap();
        assert!(matches!(
            next_event(&mut stream).await.unwrap().payload,
            Some(watch_sandboxes_event::Payload::Deleted(_))
        ));
    }

    /// If the current state cannot be read the watch fails, so the gateway
    /// reconnects and gets the snapshot, rather than silently starting from
    /// nothing.
    #[tokio::test]
    async fn watch_fails_when_current_state_cannot_be_listed() {
        let status = match service()
            .watch_sandboxes(Request::new(WatchSandboxesRequest {}))
            .await
        {
            Ok(_) => panic!("watch should fail without LXD"),
            Err(status) => status,
        };
        assert_eq!(status.code(), Code::Internal, "{status}");
    }
}
