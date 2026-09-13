// SPDX-License-Identifier: AGPL-3.0-or-later

use std::process::Command;

#[test]
fn help_lists_socket_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_openshell-driver-lxd"))
        .arg("--help")
        .output()
        .expect("failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--socket"), "stdout was:\n{stdout}");
    assert!(stdout.contains("--project"), "stdout was:\n{stdout}");
    assert!(
        stdout.contains("--dhcp-client-bin"),
        "stdout was:\n{stdout}"
    );
}

/// Without TLS materials or an explicit opt-out the driver refuses to start,
/// before it binds its socket or talks to LXD.
#[test]
fn refuses_a_plaintext_gateway_unless_allowed() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let socket = dir.path().join("driver.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_openshell-driver-lxd"))
        .arg("--socket")
        .arg(&socket)
        .args(["--lxd-socket", "/nonexistent/lxd.socket"])
        .output()
        .expect("failed to run binary");

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--guest-tls-ca") || stderr.contains("--guest-tls-ca"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!socket.exists());
}
