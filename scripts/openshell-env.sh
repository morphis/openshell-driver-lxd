#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The test environment the upstream OpenShell test suites run against: this
# driver and an OpenShell gateway on the local LXD, with the gateway, CLI and
# supervisor pinned to one OpenShell release so they always match — mixing
# releases is a known way to get failures that are not the driver's fault.
#
# Everything runs in a dedicated LXD project that is created and removed
# here, so it never touches other instances. The project shares the default
# project's images, so the sandbox image is imported once and reused.
#
# The suites source this file for its pins and functions:
#   scripts/conformance.sh   upstream's conformance scenarios
#   scripts/upstream-e2e.sh  upstream's policy, Landlock and inference tests
#
# Run directly, it manages the environment for debugging:
#
# Usage: scripts/openshell-env.sh up|down|restart-gateway|restart-driver
#
#   up               start the driver and gateway and leave them running
#   down             stop them and remove the LXD project
#   restart-gateway  restart the running gateway
#   restart-driver   restart the running driver
#
# Environment:
#   OPENSHELL_TEST_WORK_DIR   state, logs and artifacts (default: target/openshell-test)
#   OPENSHELL_TEST_CACHE_DIR  downloads and builds (default: target/openshell-test-cache)
#   OPENSHELL_TEST_PROJECT    LXD project to run in (default: openshell-test)
#   OPENSHELL_TEST_NETWORK    network sandboxes attach to (default: lxdbr0)
#   OPENSHELL_TEST_POOL       pool for sandbox root disks (default: default)
#   OPENSHELL_TEST_GATEWAY_IP host address the gateway binds and sandboxes
#                             reach it at (default: derived from the network)
#   OPENSHELL_TEST_DRIVER_ARGS  extra driver arguments (default: none)

set -euo pipefail

# --- Pins --------------------------------------------------------------------

# Bump the release here and in `OPENSHELL_REF` in the Makefile together, so
# the vendored proto matches the gateway the suites run against.
OPENSHELL_VERSION="0.0.116"
OPENSHELL_REPO="https://github.com/NVIDIA/OpenShell"
OPENSHELL_RELEASE_URL="${OPENSHELL_REPO}/releases/download/v${OPENSHELL_VERSION}"
# The commit the release tag points to, for suites that need the source.
# shellcheck disable=SC2034  # used by the suites that source this file
OPENSHELL_SOURCE_REV="d1155aa70042d3e2ee49dbfa15346b108b7c1d92"
GATEWAY_SHA256_X86_64="59c6da724eae7a00c28826f9191efbdf4fbaa5c768afdc8dea6a80a949ebcc89"
GATEWAY_SHA256_AARCH64="292c379193a339220234ffea585350901468bb8f4076e2076bc074e8ed18974b"
CLI_SHA256_X86_64="4fb4476d80a1875a0b83547ec3aba999cf0a2e2d75f95f2f709b622e2103520e"
CLI_SHA256_AARCH64="7a949c48d1e000cd280869eea1e203e24816b9cfefc575b68a8b72b939cb3f43"

# The supervisor released with the gateway, pinned by index digest.
SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor:${OPENSHELL_VERSION}@sha256:c8c42aef16c200063e32cbf72e553e4ead027085427b555efafd95063ecead42"

# The sandbox rootfs, pinned by index digest. Upstream publishes it only as
# `latest` and per-commit tags, so nothing ties a build of it to an OpenShell
# release and it moves without warning — which is how it came to ship a
# Python two minor versions ahead of what the suites were built against, and
# `exec_python` started dying on bytecode the sandbox could not run. Bumping
# this means checking SANDBOX_PYTHON_VERSION in upstream-e2e.sh with it.
# shellcheck disable=SC2034  # used by the suites that source this file
SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"

# --- Layout ------------------------------------------------------------------

ENV_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/openshell-env.sh"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${OPENSHELL_TEST_WORK_DIR:-${REPO_ROOT}/target/openshell-test}"
CACHE_DIR="${OPENSHELL_TEST_CACHE_DIR:-${REPO_ROOT}/target/openshell-test-cache}"
PROJECT="${OPENSHELL_TEST_PROJECT:-openshell-test}"
# Where sandboxes land. Both go on the test project's own default profile,
# which is where the driver reads them from: it is given nothing but
# --project, the way an operator points it at a prepared project.
NETWORK="${OPENSHELL_TEST_NETWORK:-lxdbr0}"
STORAGE_POOL="${OPENSHELL_TEST_POOL:-default}"
# Driver options the suites do not set themselves, for exercising one of its
# modes against a whole suite without a second script.
read -r -a EXTRA_DRIVER_ARGS <<<"${OPENSHELL_TEST_DRIVER_ARGS:-}"

GATEWAY_PORT=17670
HEALTH_PORT=17671

# Marks a work dir as this script's, so it is the only kind ever wiped.
WORK_DIR_MARKER=".openshell-test-work"

# Environment logs go here; each suite writes its results to a subdirectory.
ARTIFACTS_DIR="${WORK_DIR}/artifacts"
DRIVER_SOCKET="${WORK_DIR}/driver.sock"
DRIVER_BIN="${REPO_ROOT}/target/debug/openshell-driver-lxd"
OPENSHELL_DIR="${CACHE_DIR}/openshell-${OPENSHELL_VERSION}"
GATEWAY_BIN="${OPENSHELL_DIR}/openshell-gateway"
# shellcheck disable=SC2034  # used by the suites that source this file
CLI_BIN="${OPENSHELL_DIR}/openshell"

log() {
    printf '==> %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_tools() {
    local missing=()
    local tool
    for tool in lxc skopeo umoci mksquashfs curl openssl sha256sum tar git cargo ss; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        die "missing required tools: ${missing[*]}"
    fi
}

# --- Binaries ----------------------------------------------------------------

fetch_release_asset() {
    local name=$1 sha256=$2
    local archive="${OPENSHELL_DIR}/${name}"
    if [ ! -f "$archive" ]; then
        log "downloading ${name}"
        curl -fsSL --retry 3 -o "${archive}.partial" "${OPENSHELL_RELEASE_URL}/${name}"
        mv "${archive}.partial" "$archive"
    fi
    echo "${sha256}  ${archive}" | sha256sum --check --quiet \
        || die "checksum mismatch for ${name}; delete ${archive} to download it again"
    case "$name" in
        *.tar.gz) tar -xzf "$archive" -C "$OPENSHELL_DIR" ;;
    esac
}

fetch_openshell() {
    mkdir -p "$OPENSHELL_DIR"
    case "$(uname -m)" in
        x86_64)
            fetch_release_asset "openshell-gateway-x86_64-unknown-linux-gnu.tar.gz" "$GATEWAY_SHA256_X86_64"
            fetch_release_asset "openshell-x86_64-unknown-linux-musl.tar.gz" "$CLI_SHA256_X86_64"
            ;;
        aarch64)
            fetch_release_asset "openshell-gateway-aarch64-unknown-linux-gnu.tar.gz" "$GATEWAY_SHA256_AARCH64"
            fetch_release_asset "openshell-aarch64-unknown-linux-musl.tar.gz" "$CLI_SHA256_AARCH64"
            ;;
        *)
            die "unsupported architecture $(uname -m)"
            ;;
    esac
}

build_driver() {
    log "building openshell-driver-lxd"
    cargo build --quiet --manifest-path "${REPO_ROOT}/Cargo.toml" -p openshell-driver-lxd
}

# Fetches `rev` from `repo` into `dir`, checked out, leaving the `.git` in
# place for the caller to remove.
#
# Git runs with the user's and the system's configuration ignored. A
# `url.git@github.com:.insteadOf https://github.com/` rewrite is a common
# thing to have on a machine that pushes over SSH, and it would turn this
# anonymous HTTPS fetch into an SSH one, which then fails wherever that
# machine has no key for the remote — as the test hosts do not.
fetch_git_rev() {
    local dir=$1 repo=$2 rev=$3
    mkdir -p "$dir"
    local git=(env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git -C "$dir")
    "${git[@]}" init --quiet
    "${git[@]}" fetch --quiet --depth 1 "$repo" "$rev"
    "${git[@]}" checkout --quiet FETCH_HEAD
}

# --- Environment -------------------------------------------------------------

network_type() {
    lxc query "/1.0/networks/${NETWORK}" </dev/null | jq -r .type
}

# The host address the gateway binds to and sandboxes reach it at.
#
# On a bridge that is the bridge's own address, which is also what the driver
# derives when it is not told otherwise. An OVN network has no such address —
# its ipv4.address belongs to its virtual router, which nothing on the host
# can listen on — so sandboxes leave through the router's uplink address and
# see the host as whatever address routes there.
gateway_ipv4() {
    if [ -n "${OPENSHELL_TEST_GATEWAY_IP:-}" ]; then
        echo "$OPENSHELL_TEST_GATEWAY_IP"
        return
    fi
    local type cidr uplink
    type="$(network_type)"
    if [ "$type" = "ovn" ]; then
        uplink="$(lxc query "/1.0/networks/${NETWORK}" </dev/null |
            jq -r '.config["volatile.network.ipv4.address"] // empty')"
        [ -n "$uplink" ] ||
            die "OVN network ${NETWORK} has no uplink address yet; set OPENSHELL_TEST_GATEWAY_IP"
        ip -4 route get "$uplink" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1 |
            grep . || die "no host address routes to the uplink ${uplink} of ${NETWORK}"
        return
    fi
    cidr="$(lxc network get "$NETWORK" ipv4.address </dev/null)"
    if [ -z "$cidr" ] || [ "$cidr" = "none" ]; then
        die "network ${NETWORK} has no IPv4 address"
    fi
    echo "${cidr%/*}"
}

create_project() {
    if lxc project show "$PROJECT" </dev/null >/dev/null 2>&1; then
        die "LXD project ${PROJECT} already exists; run '${ENV_SCRIPT} down' first"
    fi
    log "creating LXD project ${PROJECT} (network ${NETWORK}, pool ${STORAGE_POOL})"
    lxc project create "$PROJECT" -c features.images=false -c features.profiles=true </dev/null >/dev/null
    # The project's own default profile is the only place the driver is told
    # where sandboxes go, so this is also what exercises reading it from
    # there. features.profiles=true above is what gives the project a profile
    # of its own to put this on.
    lxc profile device add default root disk path=/ pool="$STORAGE_POOL" \
        --project "$PROJECT" </dev/null >/dev/null
    lxc profile device add default eth0 nic network="$NETWORK" name=eth0 \
        --project "$PROJECT" </dev/null >/dev/null
}

delete_project() {
    lxc project show "$PROJECT" </dev/null >/dev/null 2>&1 || return 0
    log "removing LXD project ${PROJECT}"
    local name volume
    for name in $(lxc list --project "$PROJECT" --format csv -c n </dev/null); do
        lxc delete --force "$name" --project "$PROJECT" </dev/null >/dev/null 2>&1 || true
    done
    for volume in $(lxc storage volume list "$STORAGE_POOL" --project "$PROJECT" --format csv -c tn </dev/null | awk -F, '$1 == "custom" { print $2 }'); do
        lxc storage volume delete "$STORAGE_POOL" "$volume" --project "$PROJECT" </dev/null >/dev/null 2>&1 || true
    done
    lxc project delete "$PROJECT" </dev/null >/dev/null
    # The sandbox egress ACL is left behind. It belongs to the project the
    # network is in, not the one just deleted, so nothing else here takes it
    # with them.
    lxc network acl delete "openshell-egress-${NETWORK}" </dev/null >/dev/null 2>&1 || true
}

write_gateway_config() {
    local keys="${WORK_DIR}/jwt"
    mkdir -p "$keys"
    openssl genpkey -algorithm ed25519 -out "${keys}/signing.pem" 2>/dev/null
    openssl pkey -in "${keys}/signing.pem" -pubout -out "${keys}/public.pem"
    echo "openshell-test" >"${keys}/kid"
    chmod 600 "${keys}/signing.pem"

    # Schema version 1 is what v0.0.116 accepts. Without gateway_jwt the
    # gateway mints no sandbox token and the supervisor cannot connect.
    cat >"${WORK_DIR}/gateway.toml" <<EOF
[openshell]
version = 1

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${keys}/signing.pem"
public_key_path = "${keys}/public.pem"
kid_path = "${keys}/kid"
EOF
}

pid_alive() {
    local pid_file=$1
    [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null
}

stop_process() {
    local pid_file=$1
    pid_alive "$pid_file" || { rm -f "$pid_file"; return 0; }
    local pid
    pid="$(cat "$pid_file")"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 100); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$pid_file"
}

start_driver() {
    rm -f "$DRIVER_SOCKET"
    # On a bridge the driver derives the gateway endpoint from the network
    # itself, and deriving it is worth exercising. It cannot on OVN, where
    # the network's address is its virtual router's, so there it is told.
    local endpoint=()
    if [ "$(network_type)" = "ovn" ]; then
        endpoint=(--gateway-endpoint "$(gateway_endpoint)")
    fi
    # The gateway here is plaintext, as upstream's own suites run it; the
    # driver refuses one unless told this is a test environment.
    "$DRIVER_BIN" \
        --socket "$DRIVER_SOCKET" \
        --allow-plaintext-gateway \
        "${endpoint[@]}" \
        --project "$PROJECT" \
        --log-level "info,openshell_driver_lxd=debug" \
        --default-image "$SANDBOX_IMAGE" \
        --supervisor-image "$SUPERVISOR_IMAGE" \
        --supervisor-cache-dir "${WORK_DIR}/supervisor-cache" \
        --image-work-dir "${WORK_DIR}/image-work" \
        --gateway-grpc-port "$GATEWAY_PORT" \
        "${EXTRA_DRIVER_ARGS[@]}" \
        </dev/null >>"${WORK_DIR}/driver.log" 2>&1 &
    echo $! >"${WORK_DIR}/driver.pid"

    for _ in $(seq 1 100); do
        pid_alive "${WORK_DIR}/driver.pid" || break
        [ -S "$DRIVER_SOCKET" ] && return 0
        sleep 0.1
    done
    tail -n 50 "${WORK_DIR}/driver.log" >&2 || true
    die "driver did not start"
}

start_gateway() {
    local ip
    ip="$(cat "${WORK_DIR}/gateway-ip")"
    "$GATEWAY_BIN" \
        --config "${WORK_DIR}/gateway.toml" \
        --disable-tls \
        --bind-address "$ip" \
        --port "$GATEWAY_PORT" \
        --health-port "$HEALTH_PORT" \
        --drivers lxd \
        --compute-driver-socket "$DRIVER_SOCKET" \
        --db-url "sqlite:${WORK_DIR}/gateway.db?mode=rwc" \
        --log-level info \
        </dev/null >>"${WORK_DIR}/gateway.log" 2>&1 &
    echo $! >"${WORK_DIR}/gateway.pid"

    # Our own process first: a gateway left over from an earlier run answers
    # this health check just as well, and the tests would then run against
    # it — against its driver, its project and its state.
    for _ in $(seq 1 600); do
        pid_alive "${WORK_DIR}/gateway.pid" || break
        curl -fs "http://${ip}:${HEALTH_PORT}/healthz" >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    tail -n 50 "${WORK_DIR}/gateway.log" >&2 || true
    die "gateway did not become healthy"
}

# Writes an argument-less executable at `$WORK_DIR/actions/<action>` that
# runs `openshell-env.sh <action>` on this environment, for test runners
# whose host actions cannot take arguments. Prints its path.
write_host_action() {
    local action=$1
    local path="${WORK_DIR}/actions/${action}"
    mkdir -p "${WORK_DIR}/actions"
    cat >"$path" <<EOF
#!/bin/sh
OPENSHELL_TEST_WORK_DIR='${WORK_DIR}' OPENSHELL_TEST_CACHE_DIR='${CACHE_DIR}' OPENSHELL_TEST_PROJECT='${PROJECT}' \\
OPENSHELL_TEST_NETWORK='${NETWORK}' OPENSHELL_TEST_POOL='${STORAGE_POOL}' \\
OPENSHELL_TEST_DRIVER_ARGS='${OPENSHELL_TEST_DRIVER_ARGS:-}' \\
    exec '${ENV_SCRIPT}' ${action}
EOF
    chmod +x "$path"
    echo "$path"
}

gateway_endpoint() {
    echo "http://$(cat "${WORK_DIR}/gateway-ip"):${GATEWAY_PORT}"
}

# Runs a command with the CLI pointed at the gateway and its config and
# state kept in the work dir, out of the user's home.
cli_env() {
    env OPENSHELL_GATEWAY_ENDPOINT="$(gateway_endpoint)" \
        XDG_CONFIG_HOME="${WORK_DIR}/cli/config" \
        XDG_STATE_HOME="${WORK_DIR}/cli/state" \
        XDG_DATA_HOME="${WORK_DIR}/cli/data" \
        XDG_CACHE_HOME="${WORK_DIR}/cli/cache" \
        "$@"
}

# --- Commands ----------------------------------------------------------------

ensure_not_running() {
    if pid_alive "${WORK_DIR}/gateway.pid" || pid_alive "${WORK_DIR}/driver.pid"; then
        die "already running; run '${ENV_SCRIPT} down' first"
    fi
    # A gateway whose pid file is gone — a run killed part-way, or one from
    # another work dir -- still holds the ports and still answers the health
    # check the new gateway is waited on with. Refuse rather than let the
    # suites run against it.
    local port
    for port in "$GATEWAY_PORT" "$HEALTH_PORT"; do
        if ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN; then
            die "something is already listening on port ${port}; stop it first" \
                "(ss -ltnp \"sport = :${port}\")"
        fi
    done
}

env_up() {
    require_tools
    ensure_not_running
    fetch_openshell
    build_driver

    # Start from a clean work dir, but only ever wipe one this script made.
    if [ -d "$WORK_DIR" ] && [ -n "$(ls -A "$WORK_DIR")" ] && [ ! -f "${WORK_DIR}/${WORK_DIR_MARKER}" ]; then
        die "${WORK_DIR} is not empty and was not created by this script"
    fi
    # The marker goes last, so a wipe that fails part-way still leaves a work
    # dir this script recognizes as its own.
    mkdir -p "$WORK_DIR"
    touch "${WORK_DIR}/${WORK_DIR_MARKER}"
    find "$WORK_DIR" -mindepth 1 -maxdepth 1 ! -name "$WORK_DIR_MARKER" -exec rm -rf {} +
    mkdir -p "$ARTIFACTS_DIR"
    gateway_ipv4 >"${WORK_DIR}/gateway-ip"
    create_project
    write_gateway_config

    # Sandboxes are usually gone by the time a failed test returns (test
    # runners delete them), so record what LXD did to them while it happened.
    lxc monitor --project "$PROJECT" --type=lifecycle --format=json \
        </dev/null >"${ARTIFACTS_DIR}/lxd-lifecycle.json" 2>&1 &
    echo $! >"${WORK_DIR}/monitor.pid"

    log "starting driver (project ${PROJECT}, supervisor ${OPENSHELL_VERSION})"
    start_driver
    log "starting OpenShell ${OPENSHELL_VERSION} gateway on $(cat "${WORK_DIR}/gateway-ip"):${GATEWAY_PORT}"
    start_gateway
    log "up; logs in ${WORK_DIR}"
}

env_down() {
    stop_process "${WORK_DIR}/gateway.pid"
    stop_process "${WORK_DIR}/driver.pid"
    delete_project
    stop_process "${WORK_DIR}/monitor.pid"
}

env_collect_artifacts() {
    mkdir -p "$ARTIFACTS_DIR"
    cp "${WORK_DIR}/driver.log" "${WORK_DIR}/gateway.log" "${WORK_DIR}/gateway.toml" \
        "$ARTIFACTS_DIR/" 2>/dev/null || true
    {
        echo "openshell ${OPENSHELL_VERSION}"
        echo "supervisor ${SUPERVISOR_IMAGE}"
        echo "driver $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
        lxc version </dev/null 2>/dev/null || true
        snap list lxd 2>/dev/null | tail -n 1 || true
        uname -a
    } >"${ARTIFACTS_DIR}/versions.txt"
}

# Brings the environment up for a suite and tears it down, with artifacts
# collected, when the suite's script exits. Refuses before installing the
# teardown, so an environment someone brought up with `up` is left alone.
env_up_for_suite() {
    ensure_not_running
    trap 'env_collect_artifacts; env_down' EXIT
    env_up
}

# Sourcing this file (as the suites do) only defines the pins and functions
# above.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi

case "${1:-}" in
    up) env_up ;;
    down) env_down ;;
    restart-gateway)
        stop_process "${WORK_DIR}/gateway.pid"
        start_gateway
        ;;
    restart-driver)
        stop_process "${WORK_DIR}/driver.pid"
        start_driver
        ;;
    *) die "usage: $0 up|down|restart-gateway|restart-driver" ;;
esac
