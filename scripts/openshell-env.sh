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
#   OPENSHELL_TEST_NETWORK    OVN network sandboxes attach to (default: lxdbr0,
#                             which is refused: see require_ovn_network)
#   OPENSHELL_TEST_POOL       pool for sandbox root disks (default: default)
#   OPENSHELL_TEST_GATEWAY_IP host address the gateway binds and sandboxes
#                             reach it at (default: derived from the network)
#   OPENSHELL_TEST_DRIVER_ARGS  extra driver arguments (default: none)

set -euo pipefail

# --- Pins --------------------------------------------------------------------

# Bump the release here and in `OPENSHELL_REF` in the Makefile together, so
# the vendored proto matches the gateway the suites run against.
OPENSHELL_VERSION="0.1.0-pre.11"
OPENSHELL_REPO="https://github.com/NVIDIA/OpenShell"
# The commit the tag points to. The gateway and CLI are *built* from it: no
# v0.1.0-pre tag has a GitHub release, so there are no binaries to download
# and no checksums to pin. v0.0.116 was the last release with assets.
# shellcheck disable=SC2034  # used by the suites that source this file
OPENSHELL_SOURCE_REV="a8f98ec09de502bad1edc5b1a903382d27b8be0e"

# The two halves of a sandbox, pinned by digest and to the same revision as
# the gateway. A gateway, a supervisor companion and a workload boundary from
# different revisions do not make a working sandbox, and the version strings
# these images report do not say which revision they came from.
SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor:${OPENSHELL_SOURCE_REV}@sha256:79f6c249f492bb3ed8079d72fc3ae6595d03b63db800d92df63d713ebf72fe4b"
SANDBOX_BINARY_IMAGE="ghcr.io/nvidia/openshell/sandbox:${OPENSHELL_SOURCE_REV}@sha256:62338c8f73ebfec23270c4532b1b1f77d50591764f72a5d919b4d6227abceb72"

# The workload rootfs, pinned by digest: upstream's own default sandbox image.
#
# It used to be `openshell-community/sandboxes/base`, which upstream moved
# away from and has not rebuilt since May 2026 — its `/etc/openshell/policy.yaml`
# no longer parses, and a sandbox booted from it never leaves Provisioning
# ("Image policy is invalid"). A base image with no policy at all is the
# supported case: the supervisor falls back to the restrictive default.
#
# Bumping this means checking SANDBOX_PYTHON_VERSION in upstream-e2e.sh with
# it: cloudpickle ships a test's function into the sandbox as bytecode, and
# bytecode does not survive a Python version change.
# shellcheck disable=SC2034  # used by the suites that source this file
SANDBOX_IMAGE="nvcr.io/nvidia/base/ubuntu:24.04@sha256:c280ee89f8bfcbdaba6179ad4347f60c509e841cbe63eb93002f01bf70e0819c"

# --- Layout ------------------------------------------------------------------

ENV_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/openshell-env.sh"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="${OPENSHELL_TEST_WORK_DIR:-${REPO_ROOT}/target/openshell-test}"
CACHE_DIR="${OPENSHELL_TEST_CACHE_DIR:-${REPO_ROOT}/target/openshell-test-cache}"
PROJECT="${OPENSHELL_TEST_PROJECT:-openshell-test}"
# Where sandboxes land. Both go on the test project's own default profile,
# which is where the driver reads them from: it is given nothing but
# --project, the way an operator points it at a prepared project.
#
# Read from the host's own `default` profile rather than assumed. These suites
# need an OVN network now — a sandbox cannot be fenced anywhere else — and an
# OVN host is usually a MicroCloud, which has neither an `lxdbr0` nor a pool
# called `default`. `scripts/setup-ovn-test-env.sh` lays that profile out.
NETWORK="${OPENSHELL_TEST_NETWORK:-$(lxc profile device get default eth0 network </dev/null 2>/dev/null || true)}"
STORAGE_POOL="${OPENSHELL_TEST_POOL:-$(lxc profile device get default root pool </dev/null 2>/dev/null || true)}"
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

require_layout() {
    [ -n "$NETWORK" ] || die \
        "no network to put sandboxes on: the host's default profile has no eth0 NIC." \
        "Run 'make setup-ovn-test-env', or set OPENSHELL_TEST_NETWORK."
    [ -n "$STORAGE_POOL" ] || die \
        "no pool to put sandbox root disks on: the host's default profile has no root disk." \
        "Run 'make setup-ovn-test-env', or set OPENSHELL_TEST_POOL."
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

# Builds the gateway and the CLI from the pinned revision, into the cache.
#
# They used to be downloaded: every v0.0.x tag published release binaries with
# checksums to pin. No v0.1.0-pre tag has a GitHub release at all, so there is
# nothing to download, and building is the only way to run the suites against
# the release the driver targets.
#
# The build is cached by revision, so it happens once per bump rather than
# once per run. It is a large Rust workspace; expect the first one to take a
# while and to want several gigabytes of disk.
fetch_openshell() {
    local stamp="${OPENSHELL_DIR}/.built"
    if [ -x "$GATEWAY_BIN" ] && [ -x "$CLI_BIN" ] &&
        [ "$(cat "$stamp" 2>/dev/null)" = "$OPENSHELL_SOURCE_REV" ]; then
        log "reusing OpenShell ${OPENSHELL_VERSION} built at ${OPENSHELL_DIR}"
        return
    fi

    local src="${CACHE_DIR}/openshell-src-${OPENSHELL_SOURCE_REV}"
    if [ ! -f "${src}/Cargo.toml" ]; then
        log "fetching OpenShell ${OPENSHELL_VERSION} source (${OPENSHELL_SOURCE_REV})"
        rm -rf "$src"
        fetch_git_rev "$src" "$OPENSHELL_REPO" "$OPENSHELL_SOURCE_REV"
        rm -rf "${src}/.git"
    fi

    log "building openshell-gateway and the openshell CLI (this takes a while)"
    mkdir -p "$OPENSHELL_DIR"
    (
        cd "$src"
        CARGO_TARGET_DIR="${CACHE_DIR}/openshell-target" \
            cargo build --release --locked \
            -p openshell-gateway --bin openshell-gateway \
            -p openshell-cli --bin openshell </dev/null
    ) || die "building OpenShell ${OPENSHELL_VERSION} failed"

    install -m 0755 "${CACHE_DIR}/openshell-target/release/openshell-gateway" "$GATEWAY_BIN"
    install -m 0755 "${CACHE_DIR}/openshell-target/release/openshell" "$CLI_BIN"
    printf '%s\n' "$OPENSHELL_SOURCE_REV" >"$stamp"
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

# Refuses a network the driver cannot fence.
#
# From OpenShell v0.1.0 the sandbox egress ACL is the outer network fence both
# halves of a sandbox validate before the workload runs, and LXD applies a
# per-NIC ACL only on OVN. On anything else every create fails, one sandbox at
# a time; say so once, here, instead.
require_ovn_network() {
    local type
    type="$(network_type)"
    [ "$type" = "ovn" ] || die \
        "network ${NETWORK} is a ${type} network, and sandboxes need an OVN one:" \
        "their egress ACL is the outer network fence OpenShell v0.1.0 requires," \
        "and LXD applies a per-NIC ACL nowhere else." \
        "Set OPENSHELL_TEST_NETWORK to an OVN network."
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

    # Schema version 2 is what v0.1.0 accepts; a v0.0.116 file says 1 and is
    # rejected outright. Without gateway_jwt the gateway mints no launch
    # authentication, and neither half of a sandbox can authenticate.
    cat >"${WORK_DIR}/gateway.toml" <<EOF
[openshell]
version = 2

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
        --sandbox-binary-image "$SANDBOX_BINARY_IMAGE" \
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
        --compute-driver lxd \
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
    require_layout
    require_ovn_network
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
