// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stand-in for the OpenShell supervisor, used by the driver's integration
//! tests (`tests/driver_lxd`) through `--supervisor-bin`.
//!
//! The real supervisor needs a gateway: without one it gives up and exits
//! about ten seconds after start, so a sandbox cannot be held in a known state
//! long enough to test the driver against it. This binary takes its place as
//! the sandbox's init and does nothing except what a test asks for:
//!
//! - it runs until told to exit, ignoring LXD's graceful shutdown signal the
//!   same way the real supervisor does;
//! - it exits with `N` as soon as a file containing `N` appears at
//!   [`EXIT_FILE`], which a test pushes through the LXD files API to simulate
//!   the supervisor dying on its own;
//! - `ODL_STANDIN_EXIT_ON_START=N` makes it exit with `N` on every start, and
//!   `ODL_STANDIN_EXIT_ON_FIRST_START=N` only on the sandbox's first start.
//!
//! It prints its arguments and `OPENSHELL_*` environment to the console so
//! tests can check what the driver delivered to the supervisor.

use std::path::Path;
use std::process::exit;
use std::time::Duration;

/// A test writes an exit code here to make the stand-in exit.
///
/// Under `/tmp` because the boundary runs as the image's unprivileged sandbox
/// user: anywhere root-owned, the stand-in could neither record its state nor
/// clear a handled request, and it would silently behave as if every start
/// were its first.
const EXIT_FILE: &str = "/tmp/odl-standin-exit";

/// Present once the stand-in has started in this sandbox at least once.
const STARTED_MARKER: &str = "/tmp/odl-standin-started";

fn env_exit_code(key: &str) -> Option<i32> {
    std::env::var(key).ok()?.trim().parse().ok()
}

/// The bootstrap file, however the driver invoked this binary.
///
/// The companion half still gets `--bootstrap <path>`. The workload half is
/// reached through the boundary's own privilege drop — `launch-capability-free
/// <uid> <gid> <bootstrap> [workspace]` — because the init script must not
/// take a `setpriv` from the workload's own image. The stand-in stands in for
/// the boundary in both cases, so it has to read both.
fn bootstrap_path(args: &[String]) -> Option<&String> {
    if let Some(index) = args.iter().position(|arg| arg == "--bootstrap") {
        return args.get(index + 1);
    }
    let index = args
        .iter()
        .position(|arg| arg == "launch-capability-free")?;
    // <uid> <gid> <bootstrap>
    args.get(index + 3)
}

/// Applies the bootstrap's `child_env` to this process's own environment.
///
/// The real in-workload boundary injects that map into the processes it
/// starts; a sandbox's declared environment travels there and not in the
/// container's own environment. The stand-in *is* the workload as far as these
/// tests are concerned, so it does the same thing to itself — which is what
/// lets a test steer it with `template.environment`, the way a request steers
/// a real sandbox.
fn apply_child_env(args: &[String]) {
    let Some(bootstrap) = bootstrap_path(args) else {
        return;
    };
    let Ok(contents) = std::fs::read_to_string(bootstrap) else {
        // One-use: the real boundary deletes it after reading, and a restart
        // that finds it gone is not an error here.
        return;
    };
    // Deliberately not a JSON dependency: this example is built with the
    // driver's own dependencies and a hand-rolled scan of one flat string map
    // is enough for the values these tests set.
    let Some(start) = contents.find("\"child_env\"") else {
        return;
    };
    let rest = &contents[start..];
    let Some(open) = rest.find('{') else { return };
    let Some(close) = rest[open..].find('}') else {
        return;
    };
    for entry in rest[open + 1..open + close].split(',') {
        let Some((key, value)) = entry.split_once(':') else {
            continue;
        };
        let trim = |s: &str| s.trim().trim_matches('"').to_string();
        let (key, value) = (trim(key), trim(value));
        if !key.is_empty() {
            println!("odl-standin: child_env {key}={value}");
            unsafe { std::env::set_var(key, value) };
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    println!("odl-standin: started args={args:?}");
    apply_child_env(&args);

    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(key, _)| key.starts_with("OPENSHELL_"))
        .collect();
    env.sort();
    for (key, value) in env {
        println!("odl-standin: env {key}={value}");
    }

    let first_start = !Path::new(STARTED_MARKER).exists();
    if let Some(parent) = Path::new(STARTED_MARKER).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(STARTED_MARKER, b"");

    if let Some(code) = env_exit_code("ODL_STANDIN_EXIT_ON_START") {
        println!("odl-standin: exiting on start with {code}");
        exit(code);
    }
    if first_start {
        if let Some(code) = env_exit_code("ODL_STANDIN_EXIT_ON_FIRST_START") {
            println!("odl-standin: exiting on first start with {code}");
            exit(code);
        }
    }

    loop {
        if let Ok(contents) = std::fs::read_to_string(EXIT_FILE) {
            let code = contents.trim().parse().unwrap_or(1);
            // Remove the request first so a restarted sandbox keeps running.
            let _ = std::fs::remove_file(EXIT_FILE);
            println!("odl-standin: exiting on request with {code}");
            exit(code);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
