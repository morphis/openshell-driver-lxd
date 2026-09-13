// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs the real driver binary against the local LXD and talks to it over its
//! Unix socket with a gRPC client, the way the gateway does.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use computev1::pb::compute_driver_client::ComputeDriverClient;
use computev1::pb::{
    watch_sandboxes_event, CreateSandboxRequest, DeleteSandboxRequest, DriverCondition,
    DriverSandbox, DriverSandboxSpec, DriverSandboxTemplate, GetCapabilitiesRequest,
    GetSandboxRequest, ListSandboxesRequest, StartSandboxRequest, StopSandboxRequest,
    WatchSandboxesEvent, WatchSandboxesRequest,
};
use hyper_util::rt::TokioIo;
use lxd_client::{LxdClient, LxdEndpoint, DEFAULT_PROJECT};
use openshell_driver_lxd::config::{
    DEFAULT_IMAGE_CACHE_ALIAS_PREFIX, DEFAULT_LXD_SOCKET, DEFAULT_SANDBOX_IMAGE,
};
use openshell_driver_lxd::image::{ImageCache, SkopeoImporter};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Status, Streaming};

/// Rootfs every test sandbox is created from unless a test says otherwise:
/// the driver's own default, so the tests exercise the image users get.
pub const SANDBOX_IMAGE: &str = DEFAULT_SANDBOX_IMAGE;

/// The stand-in exits with the code written to this guest path.
const STANDIN_EXIT_FILE: &str = "/var/lib/odl-standin/exit";

/// Graceful stop deadline the harness gives the driver. The stand-in, like the
/// real supervisor, ignores LXD's shutdown signal, so every stop of a running
/// sandbox waits this long before forcing; keep it short.
pub const STOP_TIMEOUT_SECS: u64 = 3;

/// Upper bound for any single create. The driver has code paths with no
/// deadline of its own; a test must fail rather than hang the whole run.
pub const CREATE_TIMEOUT: Duration = Duration::from_secs(180);

/// Driver log filter: the driver and its LXD client at debug, dependencies
/// (h2 frames, WebSocket handshakes) at info.
const LOG_FILTER: &str = "info,openshell_driver_lxd=debug,lxd_client=debug";

/// How long a pushed watch event may take. LXD lifecycle events reach the
/// driver in well under a second; anything near this bound is a regression.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(10);

static NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn lxd() -> LxdClient {
    LxdClient::new(LxdEndpoint::UnixSocket(PathBuf::from(DEFAULT_LXD_SOCKET))).unwrap()
}

pub fn lxd_in(project: &str) -> LxdClient {
    lxd().with_project(project)
}

/// A short, unique LXD instance name (LXD caps names at 63 characters).
pub fn unique_name(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos();
    let n = NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("odl-{tag}-{:x}{n}", nanos % 0xffff_ffff_ffff)
}

/// The gateway-assigned id for a test sandbox. Deliberately different from
/// the name so tests notice when one is used in place of the other.
pub fn sandbox_id(name: &str) -> String {
    format!("id-{name}")
}

pub fn sandbox(name: &str) -> DriverSandbox {
    DriverSandbox {
        id: sandbox_id(name),
        name: name.to_string(),
        namespace: "default".to_string(),
        workspace: "test-workspace".to_string(),
        spec: Some(DriverSandboxSpec {
            template: Some(DriverSandboxTemplate::default()),
            ..Default::default()
        }),
        status: None,
    }
}

pub fn template_mut(sandbox: &mut DriverSandbox) -> &mut DriverSandboxTemplate {
    sandbox
        .spec
        .as_mut()
        .and_then(|spec| spec.template.as_mut())
        .expect("test sandbox has a template")
}

/// Disk-backed scratch space under the cargo target directory. Image
/// conversion needs several GiB, so it must not be the memory-backed temp dir,
/// and it must be writable without root (the driver's own default is not).
pub fn scratch_root() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("driver-lxd");
    std::fs::create_dir_all(&dir).expect("create test scratch root");
    dir
}

pub fn image_work_dir() -> PathBuf {
    scratch_root().join("image-work")
}

/// Runs `f` to completion on a fresh runtime in its own thread. Lets
/// synchronous contexts (`OnceLock` initializers, `Drop`) call async code
/// while a test's runtime is blocked on them.
fn block_on_thread<T: Send + 'static>(
    f: impl std::future::Future<Output = T> + Send + 'static,
) -> T {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime")
            .block_on(f)
    })
    .join()
    .expect("helper thread panicked")
}

/// Imports [`SANDBOX_IMAGE`] once per test run, before any driver starts.
///
/// Every test binary shares one LXD, and concurrent cold imports of the same
/// image race on its alias; importing once up front also means a driver's
/// startup pre-warm is a cache hit instead of a multi-minute import.
pub fn ensure_sandbox_image() -> String {
    static ALIAS: OnceLock<Result<String, String>> = OnceLock::new();
    ALIAS
        .get_or_init(|| {
            block_on_thread(async {
                let importer = Arc::new(SkopeoImporter::new(
                    lxd(),
                    None,
                    None,
                    None,
                    image_work_dir(),
                    Duration::from_secs(900),
                ));
                ImageCache::new(
                    lxd(),
                    importer,
                    DEFAULT_IMAGE_CACHE_ALIAS_PREFIX.to_string(),
                )
                .resolve_alias(SANDBOX_IMAGE)
                .await
                .map_err(|e| e.to_string())
            })
        })
        .clone()
        .unwrap_or_else(|e| panic!("importing {SANDBOX_IMAGE} failed: {e}"))
}

/// Path to the stand-in supervisor (`examples/standin_supervisor.rs`).
///
/// `cargo test` builds examples alongside the tests; when a filter such as
/// `--test driver_lxd` skipped it, build it here.
pub fn standin_supervisor() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let exe = std::env::current_exe().expect("current test executable");
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("test executable lives in <target>/<profile>/deps");
        let path = profile_dir.join("examples").join("standin_supervisor");
        if !path.exists() {
            let mut cmd = Command::new(option_env!("CARGO").unwrap_or("cargo"));
            cmd.args([
                "build",
                "-p",
                "openshell-driver-lxd",
                "--example",
                "standin_supervisor",
            ]);
            if profile_dir.ends_with("release") {
                cmd.arg("--release");
            }
            let status = cmd.status().expect("run cargo to build the stand-in");
            assert!(status.success(), "building standin_supervisor failed");
        }
        assert!(
            path.exists(),
            "stand-in supervisor missing at {}",
            path.display()
        );
        path
    })
    .clone()
}

/// Runs `lxc` and returns stdout, panicking with stderr on failure.
pub fn lxc(args: &[&str]) -> String {
    let output = lxc_output(args);
    assert!(
        output.status.success(),
        "lxc {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn lxc_output(args: &[&str]) -> std::process::Output {
    Command::new("lxc")
        .args(args)
        .output()
        .expect("the lxc CLI must be on PATH")
}

/// Deletes the named instances when dropped, whether the test passed or not.
pub struct Cleanup {
    project: String,
    names: Vec<String>,
}

impl Cleanup {
    pub fn new(project: &str, names: &[&str]) -> Self {
        Self {
            project: project.to_string(),
            names: names.iter().map(|n| (*n).to_string()).collect(),
        }
    }
}

impl Drop for Cleanup {
    /// Retries until each instance is gone: a delete can fail transiently
    /// while LXD is still processing a stop or start the test triggered, and
    /// a single attempt would leak the instance.
    fn drop(&mut self) {
        for name in &self.names {
            for attempt in 0..20 {
                let exists = lxc_output(&["info", name, "--project", &self.project])
                    .status
                    .success();
                if !exists {
                    break;
                }
                if attempt > 0 {
                    std::thread::sleep(Duration::from_millis(500));
                }
                let _ = lxc_output(&["delete", "--force", name, "--project", &self.project]);
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DriverOptions {
    pub project: String,
    pub default_image: String,
    /// `None` runs the stand-in supervisor; `Some(image)` extracts the real
    /// supervisor binary from `image`.
    pub supervisor_image: Option<String>,
    pub image_cache_alias_prefix: String,
    pub image_work_dir: PathBuf,
    pub start_retries: u32,
    /// Passes `--allow-plaintext-gateway`. The stand-in supervisor never
    /// connects to a gateway, so most tests need no TLS materials.
    pub allow_plaintext_gateway: bool,
    pub extra_args: Vec<String>,
}

impl Default for DriverOptions {
    fn default() -> Self {
        Self {
            project: DEFAULT_PROJECT.to_string(),
            default_image: SANDBOX_IMAGE.to_string(),
            supervisor_image: None,
            image_cache_alias_prefix: DEFAULT_IMAGE_CACHE_ALIAS_PREFIX.to_string(),
            image_work_dir: image_work_dir(),
            start_retries: 1,
            allow_plaintext_gateway: true,
            extra_args: Vec::new(),
        }
    }
}

/// A running `openshell-driver-lxd` process and a client connected to it.
pub struct Driver {
    child: Mutex<Option<Child>>,
    options: DriverOptions,
    /// Holds the socket, log and supervisor cache. Kept on disk when a test
    /// fails so the log can be inspected.
    dir: Option<tempfile::TempDir>,
    pub project: String,
}

impl Driver {
    pub async fn start() -> Self {
        Self::start_with(DriverOptions::default()).await
    }

    pub async fn start_with(options: DriverOptions) -> Self {
        let driver = Self::spawn(options);
        driver.wait_ready(Duration::from_secs(120)).await;
        driver
    }

    /// Starts the process without waiting for it to serve.
    pub fn spawn(options: DriverOptions) -> Self {
        if options.default_image == SANDBOX_IMAGE
            && options.image_cache_alias_prefix == DEFAULT_IMAGE_CACHE_ALIAS_PREFIX
        {
            ensure_sandbox_image();
        }
        // Socket paths are capped at 108 bytes, so keep this directory short.
        let dir = tempfile::Builder::new()
            .prefix("odl-")
            .tempdir()
            .expect("create driver temp dir");
        let driver = Self {
            child: Mutex::new(None),
            project: options.project.clone(),
            options,
            dir: Some(dir),
        };
        driver.launch();
        driver
    }

    fn dir(&self) -> &Path {
        self.dir
            .as_ref()
            .expect("driver dir present until drop")
            .path()
    }

    pub fn socket(&self) -> PathBuf {
        self.dir().join("driver.sock")
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir().join("driver.log")
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.log_path()).unwrap_or_default()
    }

    fn launch(&self) {
        let options = &self.options;
        let log = File::options()
            .create(true)
            .append(true)
            .open(self.log_path())
            .expect("open driver log");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_openshell-driver-lxd"));
        cmd.arg("--socket")
            .arg(self.socket())
            .args(["--log-level", LOG_FILTER])
            .args(["--project", &options.project])
            .args(["--default-image", &options.default_image])
            .args([
                "--image-cache-alias-prefix",
                &options.image_cache_alias_prefix,
            ])
            .arg("--image-work-dir")
            .arg(&options.image_work_dir)
            .arg("--supervisor-cache-dir")
            .arg(self.dir().join("supervisor-cache"))
            .args(["--stop-timeout-secs", &STOP_TIMEOUT_SECS.to_string()])
            .args(["--start-retries", &options.start_retries.to_string()]);
        match &options.supervisor_image {
            None => {
                cmd.arg("--supervisor-bin").arg(standin_supervisor());
            }
            Some(image) => {
                cmd.args(["--supervisor-image", image]);
            }
        }
        if options.allow_plaintext_gateway {
            cmd.arg("--allow-plaintext-gateway");
        }
        cmd.args(&options.extra_args)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("clone log handle"))
            .stderr(log);
        *self.child.lock().unwrap() = Some(cmd.spawn().expect("spawn openshell-driver-lxd"));
    }

    /// Waits until the driver answers GetCapabilities over its socket.
    pub async fn wait_ready(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(mut client) = self.try_client().await {
                let call = client.get_capabilities(Request::new(GetCapabilitiesRequest {}));
                if let Ok(Ok(_)) = tokio::time::timeout(Duration::from_secs(2), call).await {
                    return;
                }
            }
            if let Some(status) = self.exit_status() {
                panic!(
                    "driver exited with {status} before serving; log:\n{}",
                    self.log()
                );
            }
            assert!(
                Instant::now() < deadline,
                "driver did not serve within {timeout:?}; log:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// The process's exit status, if it has exited.
    pub fn exit_status(&self) -> Option<std::process::ExitStatus> {
        self.child
            .lock()
            .unwrap()
            .as_mut()?
            .try_wait()
            .expect("poll driver process")
    }

    /// Waits for the process to exit on its own and returns its status.
    pub async fn wait_exit(&self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.exit_status() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Kills the process without letting it clean up, like a crash.
    pub fn kill(&self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Starts a new process with the same options and socket.
    pub async fn restart(&self) {
        self.restart_without_waiting();
        self.wait_ready(Duration::from_secs(120)).await;
    }

    pub fn restart_without_waiting(&self) {
        self.kill();
        self.launch();
    }

    async fn try_client(&self) -> Result<ComputeDriverClient<Channel>, tonic::transport::Error> {
        let socket = self.socket();
        let channel =
            Endpoint::try_from("http://driver.invalid")?
                .connect_with_connector(tower::service_fn(move |_: Uri| {
                    let socket = socket.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket).await?))
                    }
                }))
                .await?;
        Ok(ComputeDriverClient::new(channel))
    }

    pub async fn client(&self) -> ComputeDriverClient<Channel> {
        self.try_client()
            .await
            .unwrap_or_else(|e| panic!("connect to driver: {e}; log:\n{}", self.log()))
    }

    /// Deletes these sandboxes' instances when the returned guard drops.
    pub fn cleanup(&self, names: &[&str]) -> Cleanup {
        Cleanup::new(&self.project, names)
    }

    pub async fn create(&self, sandbox: DriverSandbox) -> Result<(), Status> {
        let name = sandbox.name.clone();
        let mut client = self.client().await;
        let call = client.create_sandbox(Request::new(CreateSandboxRequest {
            sandbox: Some(sandbox),
        }));
        match tokio::time::timeout(CREATE_TIMEOUT, call).await {
            Ok(result) => result.map(|_| ()),
            Err(_) => panic!(
                "create {name} did not return within {CREATE_TIMEOUT:?}; log:\n{}",
                self.log()
            ),
        }
    }

    /// Creates a default sandbox and waits for it to be running.
    pub async fn create_running(&self, name: &str) {
        self.create(sandbox(name))
            .await
            .unwrap_or_else(|e| panic!("create {name}: {e}; log:\n{}", self.log()));
        let cond = self.ready_condition(name).await;
        assert_eq!(cond.status, "True", "{name} should be running: {cond:?}");
    }

    pub async fn get(&self, name: &str) -> Result<DriverSandbox, Status> {
        self.get_by(name, "").await
    }

    pub async fn get_by(&self, name: &str, id: &str) -> Result<DriverSandbox, Status> {
        self.client()
            .await
            .get_sandbox(Request::new(GetSandboxRequest {
                sandbox_id: id.to_string(),
                sandbox_name: name.to_string(),
            }))
            .await
            .map(|r| {
                r.into_inner()
                    .sandbox
                    .expect("GetSandbox returns a sandbox")
            })
    }

    pub async fn ready_condition(&self, name: &str) -> DriverCondition {
        let sandbox = self
            .get(name)
            .await
            .unwrap_or_else(|e| panic!("get {name}: {e}"));
        ready_condition_of(&sandbox)
    }

    pub async fn list(&self) -> Vec<DriverSandbox> {
        self.client()
            .await
            .list_sandboxes(Request::new(ListSandboxesRequest {}))
            .await
            .expect("list_sandboxes")
            .into_inner()
            .sandboxes
    }

    pub async fn stop(&self, name: &str) -> Result<(), Status> {
        self.stop_by(name, "").await
    }

    pub async fn stop_by(&self, name: &str, id: &str) -> Result<(), Status> {
        self.client()
            .await
            .stop_sandbox(Request::new(StopSandboxRequest {
                sandbox_id: id.to_string(),
                sandbox_name: name.to_string(),
            }))
            .await
            .map(|_| ())
    }

    pub async fn start_sandbox(&self, name: &str) -> Result<(), Status> {
        self.client()
            .await
            .start_sandbox(Request::new(StartSandboxRequest {
                sandbox_id: String::new(),
                sandbox_name: name.to_string(),
            }))
            .await
            .map(|_| ())
    }

    pub async fn delete(&self, name: &str) -> Result<bool, Status> {
        self.delete_by(name, "").await
    }

    pub async fn delete_by(&self, name: &str, id: &str) -> Result<bool, Status> {
        self.client()
            .await
            .delete_sandbox(Request::new(DeleteSandboxRequest {
                sandbox_id: id.to_string(),
                sandbox_name: name.to_string(),
            }))
            .await
            .map(|r| r.into_inner().deleted)
    }

    pub async fn watch(&self) -> Watch {
        let stream = self
            .client()
            .await
            .watch_sandboxes(Request::new(WatchSandboxesRequest {}))
            .await
            .expect("open WatchSandboxes")
            .into_inner();
        Watch {
            stream,
            seen: Vec::new(),
        }
    }

    /// Makes the sandbox's stand-in supervisor exit with `code`, as if the
    /// real supervisor had died.
    pub async fn exit_supervisor(&self, name: &str, code: i32) {
        lxd_in(&self.project)
            .push_file_into_instance(name, STANDIN_EXIT_FILE, code.to_string().as_bytes())
            .await
            .expect("push stand-in exit request");
    }

    /// The instance's console log, where the stand-in reports what it saw.
    pub fn console_log(&self, name: &str) -> String {
        lxc(&["console", name, "--show-log", "--project", &self.project])
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.kill();
        if std::thread::panicking() {
            eprintln!(
                "----- driver log ({}) -----\n{}----- end driver log -----",
                self.log_path().display(),
                self.log()
            );
            if let Some(dir) = self.dir.take() {
                let _ = dir.keep();
            }
        }
    }
}

pub fn ready_condition_of(sandbox: &DriverSandbox) -> DriverCondition {
    sandbox
        .status
        .as_ref()
        .and_then(|s| s.conditions.iter().find(|c| c.r#type == "Ready"))
        .cloned()
        .unwrap_or_else(|| panic!("sandbox has no Ready condition: {sandbox:?}"))
}

/// A WatchSandboxes stream plus everything it has yielded, for diagnostics.
pub struct Watch {
    stream: Streaming<WatchSandboxesEvent>,
    seen: Vec<WatchSandboxesEvent>,
}

impl Watch {
    /// Returns the first event matching `pred` within `timeout`, or `None`.
    pub async fn next_matching(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&WatchSandboxesEvent) -> bool,
    ) -> Option<WatchSandboxesEvent> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let message = tokio::time::timeout_at(deadline, self.stream.message()).await;
            match message {
                Err(_) => return None,
                Ok(Err(status)) => panic!("watch stream failed: {status}"),
                Ok(Ok(None)) => panic!("watch stream ended"),
                Ok(Ok(Some(event))) => {
                    self.seen.push(event.clone());
                    if pred(&event) {
                        return Some(event);
                    }
                }
            }
        }
    }

    /// Waits for a pushed snapshot of sandbox `id` whose Ready condition has
    /// `status` and `reason`.
    pub async fn expect_snapshot(&mut self, id: &str, status: &str, reason: &str) -> DriverSandbox {
        let event = self
            .next_matching(PUSH_TIMEOUT, |event| {
                snapshot_of(event, id).is_some_and(|sandbox| {
                    let cond = ready_condition_of(sandbox);
                    cond.status == status && cond.reason == reason
                })
            })
            .await;
        match event {
            Some(event) => snapshot_of(&event, id).cloned().unwrap(),
            None => panic!(
                "no snapshot of {id} with Ready={status} reason={reason:?} within {PUSH_TIMEOUT:?}; saw {:#?}",
                self.seen
            ),
        }
    }

    pub async fn expect_deleted(&mut self, id: &str) {
        let event = self
            .next_matching(PUSH_TIMEOUT, |event| deleted_id(event) == Some(id))
            .await;
        assert!(
            event.is_some(),
            "no Deleted event for {id} within {PUSH_TIMEOUT:?}; saw {:#?}",
            self.seen
        );
    }

    /// Asserts that nothing about `name` arrives within `wait`.
    pub async fn expect_silence_about(&mut self, name: &str, id: &str, wait: Duration) {
        let event = self
            .next_matching(wait, |event| match &event.payload {
                Some(watch_sandboxes_event::Payload::Sandbox(s)) => s
                    .sandbox
                    .as_ref()
                    .is_some_and(|s| s.name == name || s.id == id),
                Some(watch_sandboxes_event::Payload::Deleted(d)) => d.sandbox_id == id,
                _ => false,
            })
            .await;
        assert!(event.is_none(), "unexpected event about {name}: {event:?}");
    }
}

pub fn snapshot_of<'a>(event: &'a WatchSandboxesEvent, id: &str) -> Option<&'a DriverSandbox> {
    match &event.payload {
        Some(watch_sandboxes_event::Payload::Sandbox(s)) => {
            s.sandbox.as_ref().filter(|sandbox| sandbox.id == id)
        }
        _ => None,
    }
}

pub fn deleted_id(event: &WatchSandboxesEvent) -> Option<&str> {
    match &event.payload {
        Some(watch_sandboxes_event::Payload::Deleted(d)) => Some(d.sandbox_id.as_str()),
        _ => None,
    }
}

/// Polls `f` until it returns `Some`, or panics with `what` after `timeout`.
pub async fn eventually<T, F, Fut>(timeout: Duration, what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = f().await {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {timeout:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The IPv4 address of the host side of `network`, e.g. `10.146.74.1`.
pub async fn bridge_ipv4(network: &str) -> String {
    let network = lxd().get_network(network).await.expect("get network");
    let cidr = network
        .config
        .get("ipv4.address")
        .expect("network has ipv4.address");
    cidr.split('/').next().unwrap().to_string()
}

pub fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}
