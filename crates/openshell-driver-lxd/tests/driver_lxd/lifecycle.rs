// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sandbox lifecycle RPCs: create, get, list, stop, delete, and the
//! identity, idempotency and error-code rules the gateway relies on.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use computev1::pb::DriverResourceRequirements;
use prost_types::value::Kind;
use prost_types::{Struct, Value};
use tonic::Code;

use crate::harness::*;

fn string_value(s: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(s.to_string())),
    }
}

#[tokio::test]
async fn create_get_list_stop_delete_lifecycle() {
    let driver = Driver::start().await;
    let name = unique_name("life");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);

    driver
        .create(sandbox(&name))
        .await
        .expect("create_sandbox should succeed");

    let got = driver.get(&name).await.expect("get_sandbox should succeed");
    assert_eq!(got.name, name);
    assert_eq!(got.id, id);
    assert_eq!(got.namespace, "default");
    assert_eq!(got.workspace, "test-workspace");
    let cond = ready_condition_of(&got);
    assert_eq!((cond.status.as_str(), cond.reason.as_str()), ("True", ""));

    // The supervisor and DHCP client arrive as read-only volumes.
    let instance = lxd().get_instance(&name).await.expect("raw get_instance");
    for (device, path) in [
        ("supervisor", "/opt/openshell/bin"),
        ("dhcp-client", "/opt/openshell/net"),
    ] {
        let dev = instance
            .devices
            .get(device)
            .unwrap_or_else(|| panic!("{device} device should be attached"));
        assert_eq!(dev.get("type").map(String::as_str), Some("disk"));
        assert_eq!(dev.get("path").map(String::as_str), Some(path));
        assert_eq!(dev.get("readonly").map(String::as_str), Some("true"));
    }

    let listed = driver.list().await;
    assert!(
        listed.iter().any(|s| s.id == id && s.name == name),
        "expected {name} in {listed:?}"
    );

    driver
        .stop(&name)
        .await
        .expect("stop_sandbox should succeed");
    let cond = driver.ready_condition(&name).await;
    assert_eq!(
        (cond.status.as_str(), cond.reason.as_str()),
        ("False", "ContainerStopped")
    );

    // The gateway reconciles against List; a stopped sandbox must stay in it
    // or the gateway eventually treats it as gone.
    let listed = driver.list().await;
    let stopped = listed
        .iter()
        .find(|s| s.id == id)
        .unwrap_or_else(|| panic!("stopped sandbox should still be listed: {listed:?}"));
    assert_eq!(ready_condition_of(stopped).reason, "ContainerStopped");

    assert!(driver
        .delete(&name)
        .await
        .expect("delete_sandbox should succeed"));
    let status = driver
        .get(&name)
        .await
        .expect_err("deleted sandbox is gone");
    assert_eq!(status.code(), Code::NotFound);
    assert!(!driver.list().await.iter().any(|s| s.id == id));

    let deleted_again = driver
        .delete(&name)
        .await
        .expect("deleting an already-gone sandbox should succeed, not error");
    assert!(!deleted_again);
}

#[tokio::test]
async fn create_sandbox_fallback_dhcp_without_builtin_client() {
    let driver = Driver::start().await;
    let name = unique_name("dhcp");
    let _cleanup = driver.cleanup(&[&name]);

    driver.create_running(&name).await;

    // The base image ships no DHCP client of its own; eth0 must still get a
    // lease through the bundled fallback client.
    eventually(Duration::from_secs(20), "an IPv4 lease on eth0", || async {
        let state = lxd().get_instance_state(&name).await.ok()?;
        state
            .network
            .get("eth0")?
            .addresses
            .iter()
            .any(|a| a.family == "inet" && a.scope == "global" && !a.address.is_empty())
            .then_some(())
    })
    .await;

    driver
        .stop(&name)
        .await
        .expect("stop_sandbox should succeed");
    assert!(driver
        .delete(&name)
        .await
        .expect("delete_sandbox should succeed"));
}

/// What the gateway puts in the request must reach the instance and the
/// supervisor process, and the token must reach only its file.
#[tokio::test]
async fn created_instance_carries_the_request() {
    let driver = Driver::start().await;
    let name = unique_name("req");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    let token = format!("test-token-{name}");

    let mut request = sandbox(&name);
    {
        let spec = request.spec.as_mut().unwrap();
        spec.sandbox_token = token.clone();
        spec.environment = env(&[("FROM_SPEC", "spec"), ("SHARED", "spec")]);
    }
    {
        let template = template_mut(&mut request);
        template.environment = env(&[("SHARED", "template")]);
        template.labels = env(&[("team", "infra")]);
        template.resources = Some(DriverResourceRequirements {
            cpu_limit: "1".to_string(),
            memory_limit: "512Mi".to_string(),
            ..Default::default()
        });
        template.driver_config = Some(Struct {
            fields: BTreeMap::from([("max_processes".to_string(), string_value("512"))]),
        });
    }
    driver
        .create(request)
        .await
        .expect("create_sandbox should succeed");

    let config = lxd()
        .get_instance(&name)
        .await
        .expect("raw get_instance")
        .config;
    let expected_endpoint = format!("http://{}:17670", bridge_ipv4("lxdbr0").await);
    for (key, value) in [
        ("user.openshell.sandbox_id", id.as_str()),
        ("user.openshell.label.team", "infra"),
        ("environment.OPENSHELL_SANDBOX_ID", id.as_str()),
        ("environment.OPENSHELL_SANDBOX", name.as_str()),
        ("environment.OPENSHELL_ENDPOINT", expected_endpoint.as_str()),
        (
            "environment.OPENSHELL_SANDBOX_TOKEN_FILE",
            "/etc/openshell/auth/sandbox.jwt",
        ),
        ("environment.FROM_SPEC", "spec"),
        ("environment.SHARED", "template"),
        ("limits.cpu", "1"),
        ("limits.memory", "512MiB"),
        ("limits.processes", "512"),
    ] {
        assert_eq!(config.get(key).map(String::as_str), Some(value), "{key}");
    }
    assert!(
        config.values().all(|v| !v.contains(&token)),
        "the sandbox token must not be written into instance config"
    );

    let (content, mode) = lxd()
        .get_file_from_instance(&name, "/etc/openshell/auth/sandbox.jwt")
        .await
        .expect("token file should exist in the sandbox");
    assert_eq!(content.as_ref(), token.as_bytes());
    assert_eq!(mode, 0o400);

    // The supervisor itself is started with that environment.
    let console = eventually(
        Duration::from_secs(15),
        "the stand-in to report",
        || async {
            let log = driver.console_log(&name);
            log.contains("odl-standin: env OPENSHELL_SANDBOX=")
                .then_some(log)
        },
    )
    .await;
    for line in [
        format!("odl-standin: env OPENSHELL_SANDBOX_ID={id}"),
        format!("odl-standin: env OPENSHELL_ENDPOINT={expected_endpoint}"),
        "odl-standin: env OPENSHELL_SANDBOX_TOKEN_FILE=/etc/openshell/auth/sandbox.jwt".to_string(),
        "odl-standin: env OPENSHELL_SSH_SOCKET_PATH=/run/openshell/ssh.sock".to_string(),
    ] {
        assert!(
            console.contains(&line),
            "missing {line:?} in console:\n{console}"
        );
    }
    assert!(
        console.contains(r#""/opt/openshell/bin/openshell-sandbox", "--workdir", "/sandbox""#),
        "supervisor should be exec'd with --workdir /sandbox:\n{console}"
    );
}

/// The command a sandbox is created with reaches the supervisor intact,
/// arguments with spaces, quotes and non-ASCII included, through LXD's
/// environment config and the init script.
#[tokio::test]
async fn requested_command_reaches_the_supervisor() {
    let driver = Driver::start().await;
    let name = unique_name("cmd");
    let _cleanup = driver.cleanup(&[&name]);
    let command = vec![
        "sh".to_string(),
        "-lc".to_string(),
        "printf '%s\\n' \"quoted $HOME\" > /sandbox/out; echo ünïcode".to_string(),
    ];

    let mut request = sandbox(&name);
    {
        let spec = request.spec.as_mut().unwrap();
        spec.command = command.clone();
        spec.tty = false;
    }
    driver
        .create(request)
        .await
        .expect("create_sandbox should succeed");

    let prefix = "odl-standin: env OPENSHELL_MAIN_PROCESS_SPEC=";
    let line = eventually(
        Duration::from_secs(15),
        "the stand-in to report",
        || async {
            driver
                .console_log(&name)
                .lines()
                .find_map(|line| line.trim_end().strip_prefix(prefix).map(str::to_string))
        },
    )
    .await;
    let decoded: serde_json::Value =
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}"));
    assert_eq!(
        decoded,
        serde_json::json!({"version": 1, "command": command, "tty": false})
    );
}

/// The supervisor ignores LXD's graceful shutdown, so a stop is only ever as
/// long as the graceful deadline plus the forced stop.
#[tokio::test]
async fn stopping_a_running_sandbox_is_bounded() {
    let driver = Driver::start().await;
    let name = unique_name("stop");
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    let started = Instant::now();
    driver
        .stop(&name)
        .await
        .expect("stop_sandbox should succeed");
    let elapsed = started.elapsed();

    let bound = Duration::from_secs(STOP_TIMEOUT_SECS + 15);
    assert!(elapsed < bound, "stop took {elapsed:?}, bound {bound:?}");
    let instance = lxd().get_instance(&name).await.unwrap();
    assert_eq!(instance.status, "Stopped");

    // Stopping again is a no-op, not an error.
    let started = Instant::now();
    driver
        .stop(&name)
        .await
        .expect("stopping a stopped sandbox should succeed");
    assert!(started.elapsed() < Duration::from_secs(STOP_TIMEOUT_SECS));
    assert_eq!(
        driver.ready_condition(&name).await.reason,
        "ContainerStopped"
    );
}

#[tokio::test]
async fn sandbox_is_addressable_by_id_alone() {
    let driver = Driver::start().await;
    let name = unique_name("byid");
    let id = sandbox_id(&name);
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    let got = driver.get_by("", &id).await.expect("get by id alone");
    assert_eq!(got.name, name);

    driver.stop_by("", &id).await.expect("stop by id alone");
    assert_eq!(
        driver.ready_condition(&name).await.reason,
        "ContainerStopped"
    );

    assert!(driver.delete_by("", &id).await.expect("delete by id alone"));
    assert!(lxd().get_instance(&name).await.is_err());
}

#[tokio::test]
async fn deleting_a_running_sandbox_needs_no_stop() {
    let driver = Driver::start().await;
    let name = unique_name("delrun");
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    assert!(driver
        .delete(&name)
        .await
        .expect("delete_sandbox should succeed"));
    assert!(lxd().get_instance(&name).await.is_err());
}

#[tokio::test]
async fn unknown_sandboxes_are_not_found() {
    let driver = Driver::start().await;
    let missing = unique_name("missing");

    for (what, result) in [
        ("get by name", driver.get(&missing).await.map(|_| ())),
        (
            "get by id",
            driver.get_by("", &sandbox_id(&missing)).await.map(|_| ()),
        ),
        ("stop by name", driver.stop(&missing).await),
    ] {
        let status = result.expect_err(what);
        assert_eq!(status.code(), Code::NotFound, "{what}: {status}");
    }

    let deleted = driver
        .delete(&missing)
        .await
        .expect("deleting an unknown name should succeed");
    assert!(!deleted);
}

/// Delete is idempotent however the caller identifies the sandbox: an
/// unknown id is `deleted: false`, like an unknown name.
#[tokio::test]
async fn deleting_an_unknown_id_is_idempotent() {
    let driver = Driver::start().await;
    let missing = unique_name("missing");

    let deleted = driver
        .delete_by("", &sandbox_id(&missing))
        .await
        .expect("deleting an unknown id should succeed");
    assert!(!deleted);
}

#[tokio::test]
async fn empty_identity_is_invalid_argument() {
    let driver = Driver::start().await;

    let status = driver
        .get_by("", "")
        .await
        .expect_err("get without identity");
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn unmanaged_instance_is_treated_as_not_found() {
    let driver = Driver::start().await;
    let name = unique_name("unmanaged");
    let _cleanup = driver.cleanup(&[&name]);
    let alias = ensure_sandbox_image();

    // Created behind the driver's back, so it has no sandbox id marker.
    lxc(&["init", &alias, &name]);

    let status = driver.get(&name).await.expect_err("get unmanaged");
    assert_eq!(status.code(), Code::NotFound);
    let status = driver.stop(&name).await.expect_err("stop unmanaged");
    assert_eq!(status.code(), Code::NotFound);
    assert!(!driver.list().await.iter().any(|s| s.name == name));

    let deleted = driver
        .delete(&name)
        .await
        .expect("delete_sandbox should not error on an unmanaged instance");
    assert!(!deleted);
    assert!(
        lxd().get_instance(&name).await.is_ok(),
        "the driver must not delete an instance it does not manage"
    );
}

/// With `--gateway-endpoint` sandboxes get that URL rather than one derived
/// from their network, so a gateway that does not listen on the bridge — in
/// an instance, or behind an OVN network — is reachable.
#[tokio::test]
async fn explicit_gateway_endpoint_reaches_the_instance() {
    let endpoint = "http://192.0.2.10:17670";
    let driver = Driver::start_with(DriverOptions {
        extra_args: vec!["--gateway-endpoint".into(), endpoint.into()],
        ..Default::default()
    })
    .await;
    let name = unique_name("endpoint");
    let _cleanup = driver.cleanup(&[&name]);

    driver
        .create(sandbox(&name))
        .await
        .expect("create_sandbox should succeed");

    let config = lxd()
        .get_instance(&name)
        .await
        .expect("raw get_instance")
        .config;
    assert_eq!(
        config
            .get("environment.OPENSHELL_ENDPOINT")
            .map(String::as_str),
        Some(endpoint)
    );
}

/// The init script points `host.openshell.internal` at the gateway endpoint's
/// address, whether the endpoint names an IPv6 address or a host, and seeds
/// nothing for a host it cannot resolve rather than writing a name where
/// `/etc/hosts` needs an address.
#[tokio::test]
async fn host_alias_follows_the_gateway_endpoint() {
    for (endpoint, expected) in [
        ("http://[fd42::5]:17670", Some(vec!["fd42::5"])),
        ("http://localhost:17670", Some(vec!["127.0.0.1", "::1"])),
        ("http://gateway.invalid:17670", None),
    ] {
        let driver = Driver::start_with(DriverOptions {
            extra_args: vec!["--gateway-endpoint".into(), endpoint.into()],
            ..Default::default()
        })
        .await;
        let name = unique_name("alias");
        let _cleanup = driver.cleanup(&[&name]);
        driver.create_running(&name).await;

        // The init script logs the outcome before handing over to the
        // supervisor.
        let log = eventually(Duration::from_secs(60), "the init script", || async {
            let log = driver.console_log(&name);
            (log.contains("seeded /etc/hosts") || log.contains("not seeded")).then_some(log)
        })
        .await;
        let (hosts, _) = lxd()
            .get_file_from_instance(&name, "/etc/hosts")
            .await
            .expect("read /etc/hosts");
        let alias = String::from_utf8_lossy(&hosts)
            .lines()
            .find(|line| line.contains("host.openshell.internal"))
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string()
            });

        match expected {
            Some(addresses) => assert!(
                alias.as_deref().is_some_and(|a| addresses.contains(&a)),
                "{endpoint}: alias {alias:?}, expected one of {addresses:?}; console:\n{log}"
            ),
            None => {
                assert_eq!(alias, None, "{endpoint}: console:\n{log}");
                assert!(
                    log.contains("cannot resolve gateway host"),
                    "{endpoint}: {log}"
                );
            }
        }
    }
}

/// With TLS materials sandboxes get an https endpoint and the materials at
/// the paths the supervisor reads, readable by root only.
#[tokio::test]
async fn guest_tls_materials_reach_the_instance() {
    let tls_dir = tempfile::tempdir().expect("create TLS dir");
    let files = [
        (
            "ca.crt",
            "--guest-tls-ca",
            "OPENSHELL_TLS_CA",
            "/etc/openshell/tls/client/ca.crt",
        ),
        (
            "tls.crt",
            "--guest-tls-cert",
            "OPENSHELL_TLS_CERT",
            "/etc/openshell/tls/client/tls.crt",
        ),
        (
            "tls.key",
            "--guest-tls-key",
            "OPENSHELL_TLS_KEY",
            "/etc/openshell/tls/client/tls.key",
        ),
    ];
    let mut extra_args = Vec::new();
    for (file, flag, _, _) in files {
        let path = tls_dir.path().join(file);
        std::fs::write(&path, format!("test {file}")).expect("write TLS material");
        extra_args.extend([flag.to_string(), path.display().to_string()]);
    }
    extra_args.extend([
        "--gateway-tls-server-name".to_string(),
        "gateway.openshell.internal".to_string(),
    ]);
    let driver = Driver::start_with(DriverOptions {
        allow_plaintext_gateway: false,
        extra_args,
        ..Default::default()
    })
    .await;
    let name = unique_name("tls");
    let _cleanup = driver.cleanup(&[&name]);

    driver
        .create(sandbox(&name))
        .await
        .expect("create_sandbox should succeed");

    let config = lxd()
        .get_instance(&name)
        .await
        .expect("raw get_instance")
        .config;
    let expected_endpoint = format!("https://{}:17670", bridge_ipv4("lxdbr0").await);
    assert_eq!(
        config
            .get("environment.OPENSHELL_ENDPOINT")
            .map(String::as_str),
        Some(expected_endpoint.as_str())
    );
    assert_eq!(
        config
            .get("environment.OPENSHELL_GATEWAY_TLS_SERVER_NAME")
            .map(String::as_str),
        Some("gateway.openshell.internal")
    );
    for (file, _, env, guest_path) in files {
        assert_eq!(
            config
                .get(&format!("environment.{env}"))
                .map(String::as_str),
            Some(guest_path),
            "{env}"
        );
        let (content, mode) = lxd()
            .get_file_from_instance(&name, guest_path)
            .await
            .unwrap_or_else(|e| panic!("{guest_path} should exist in the sandbox: {e}"));
        assert_eq!(content.as_ref(), format!("test {file}").as_bytes());
        assert_eq!(mode, 0o400, "{guest_path}");
    }
}

/// A rejected create must not leave anything behind in LXD.
#[tokio::test]
async fn invalid_creates_are_rejected_without_leftovers() {
    let driver = Driver::start().await;

    let mut bad_label = sandbox(&unique_name("badlabel"));
    template_mut(&mut bad_label).labels = env(&[("not a key", "x")]);

    let mut bad_quantity = sandbox(&unique_name("badqty"));
    template_mut(&mut bad_quantity).resources = Some(DriverResourceRequirements {
        memory_limit: "lots".to_string(),
        ..Default::default()
    });

    let mut bad_network = sandbox(&unique_name("badnet"));
    template_mut(&mut bad_network).driver_config = Some(Struct {
        fields: BTreeMap::from([("network".to_string(), string_value("odl-no-such-net"))]),
    });

    let mut bad_pool = sandbox(&unique_name("badpool"));
    template_mut(&mut bad_pool).driver_config = Some(Struct {
        fields: BTreeMap::from([("storage_pool".to_string(), string_value("odl-no-such-pool"))]),
    });

    for (request, code) in [
        (bad_label, Code::InvalidArgument),
        (bad_quantity, Code::InvalidArgument),
        (bad_network, Code::FailedPrecondition),
        (bad_pool, Code::FailedPrecondition),
    ] {
        let name = request.name.clone();
        let _cleanup = driver.cleanup(&[&name]);
        let status = driver
            .create(request)
            .await
            .expect_err("invalid create should be rejected");
        assert_eq!(status.code(), code, "{name}: {status}");
        assert!(
            lxd().get_instance(&name).await.is_err(),
            "{name} should not exist after a rejected create"
        );
    }
}

/// Creating over an existing sandbox must fail without touching it.
#[tokio::test]
async fn duplicate_create_fails_and_keeps_the_original() {
    let driver = Driver::start().await;
    let name = unique_name("dup");
    let _cleanup = driver.cleanup(&[&name]);
    driver.create_running(&name).await;

    let mut duplicate = sandbox(&name);
    duplicate.id = format!("other-{name}");
    let status = driver
        .create(duplicate)
        .await
        .expect_err("creating an existing name should fail");
    assert_eq!(status.code(), Code::AlreadyExists, "{status}");

    let original = driver.get(&name).await.expect("original still exists");
    assert_eq!(original.id, sandbox_id(&name));
    assert_eq!(ready_condition_of(&original).status, "True");
}

/// An init that exits right after the first start (the supervisor losing a
/// start-up race) is restarted once and the sandbox comes up.
#[tokio::test]
async fn init_that_exits_once_is_restarted() {
    let driver = Driver::start().await;
    let name = unique_name("flaky");
    let _cleanup = driver.cleanup(&[&name]);

    let mut request = sandbox(&name);
    template_mut(&mut request).environment = env(&[("ODL_STANDIN_EXIT_ON_FIRST_START", "1")]);
    driver
        .create(request)
        .await
        .expect("create_sandbox should succeed");

    let cond = driver.ready_condition(&name).await;
    assert_eq!(
        cond.status, "True",
        "sandbox should be running after one restart: {cond:?}"
    );
    assert!(
        driver
            .log()
            .contains("sandbox init exited immediately after start; restarting"),
        "driver should log the restart"
    );
}

#[tokio::test]
async fn start_retries_zero_leaves_an_exited_init_down() {
    let driver = Driver::start_with(DriverOptions {
        start_retries: 0,
        ..Default::default()
    })
    .await;
    let name = unique_name("noretry");
    let _cleanup = driver.cleanup(&[&name]);

    let mut request = sandbox(&name);
    template_mut(&mut request).environment = env(&[("ODL_STANDIN_EXIT_ON_FIRST_START", "1")]);
    let _ = driver.create(request).await;

    let cond = eventually(Duration::from_secs(15), "the sandbox to stop", || async {
        let cond = driver.ready_condition(&name).await;
        (cond.status == "False").then_some(cond)
    })
    .await;
    assert_eq!(cond.reason, "ContainerExited");
    assert!(!driver.log().contains("restarting"));
}

/// An init that exits on every start ends up reported as exited: terminal at
/// the gateway, never a sandbox stuck provisioning.
#[tokio::test]
async fn init_that_keeps_exiting_is_reported_exited() {
    let driver = Driver::start().await;
    let name = unique_name("crash");
    let _cleanup = driver.cleanup(&[&name]);

    let mut request = sandbox(&name);
    template_mut(&mut request).environment = env(&[("ODL_STANDIN_EXIT_ON_START", "3")]);
    let _ = driver.create(request).await;

    let cond = eventually(Duration::from_secs(15), "the sandbox to stop", || async {
        let cond = driver.ready_condition(&name).await;
        (cond.status == "False").then_some(cond)
    })
    .await;
    assert_eq!(cond.reason, "ContainerExited");
}

/// A sandbox that died says why and where to look: the gateway shows the
/// condition message to the user next to the reason.
#[tokio::test]
async fn exited_sandbox_explains_why() {
    let driver = Driver::start().await;
    let name = unique_name("why");
    let _cleanup = driver.cleanup(&[&name]);

    let mut request = sandbox(&name);
    template_mut(&mut request).environment = env(&[("ODL_STANDIN_EXIT_ON_START", "3")]);
    let _ = driver.create(request).await;

    let cond = eventually(Duration::from_secs(15), "the sandbox to stop", || async {
        let cond = driver.ready_condition(&name).await;
        (cond.status == "False").then_some(cond)
    })
    .await;
    assert!(
        cond.message
            .contains(&format!("lxc console {name} --show-log")),
        "{cond:?}"
    );
    assert!(driver
        .console_log(&name)
        .contains("odl-standin: exiting on start with 3"));
}
