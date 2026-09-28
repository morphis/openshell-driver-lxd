#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs upstream OpenShell's end-to-end tests for sandbox policy enforcement,
# Landlock and inference routing against an OpenShell gateway backed by this
# driver on the local LXD.
#
# The conformance suite (scripts/conformance.sh) checks that sandboxes work;
# these tests check that what runs inside them is actually confined: network
# policy at L4 and L7, SSRF protections, credential handling, live policy
# updates, Landlock filesystem rules, and `inference.local` routing. The
# supervisor does the enforcing, but it depends on what the container lets
# it do (network namespaces, Landlock, seccomp), and a sandbox that silently
# enforces nothing still passes a smoke test.
#
# It runs in the environment scripts/openshell-env.sh provides, with its
# pinned OpenShell release. The tests come from that release's source tree:
# the Rust tests of `e2e/rust` that drive the CLI against an existing
# gateway, and the Python tests of `e2e/python` through the release's Python
# SDK.
#
# Usage: scripts/upstream-e2e.sh
#
# Environment (in addition to the OPENSHELL_TEST_* variables):
#   UPSTREAM_E2E_RUST_TESTS    space-separated Rust test targets to run
#   UPSTREAM_E2E_PYTHON_TESTS  space-separated Python test files to run
#
# Needs rootless podman (with uidmap and passt) for the fixture server the
# forward-proxy L7 tests start, and python3 >= 3.11.

set -euo pipefail

# shellcheck source=scripts/openshell-env.sh
. "$(dirname "${BASH_SOURCE[0]}")/openshell-env.sh"

# --- Pins --------------------------------------------------------------------

# The sandbox image these tests need, which is not the driver's default.
#
# Upstream's e2e policies name `run_as_user: sandbox` explicitly (see
# `e2e/rust/tests/landlock.rs`), and a driver must resolve an admitted identity
# selector against the pinned image or refuse the sandbox — upstream's own
# Podman driver refuses it too. So the suite needs an image that defines that
# account, and the community base image is the one that does (uid 998).
#
# It is deliberately not the driver's default. That image has not been rebuilt
# since May 2026 and the `/etc/openshell/policy.yaml` it ships no longer
# parses, which breaks a sandbox created with no policy at all. It does not
# break these tests: every one of them supplies a policy, and the supervisor
# only falls back to the image's own when the gateway has none.
#
# Assigned after openshell-env.sh is sourced, so this overrides its default;
# `start_driver` there is what reads it.
# shellcheck disable=SC2034  # read by the sourced openshell-env.sh
SANDBOX_IMAGE="ghcr.io/nvidia/openshell-community/sandboxes/base:latest@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"

# The version the Python SDK is installed as.
#
# It is built from the source tree now rather than from a release wheel, and
# upstream's pyproject.toml derives its version with setuptools-scm, which has
# no `.git` to read here and no configured fallback. So it is told. The value
# only has to be a valid PEP 440 version — nothing in the suites reads it —
# and `0.1.0-pre.11` is not one.
SDK_VERSION="0.1.0rc11"

# Python the test environment is built with. cloudpickle, which the SDK's
# exec_python uses to ship a test's function into the sandbox, serializes the
# function's bytecode, and bytecode does not survive a Python version change:
# the sandbox loads the function and then dies on the first call, with no
# output for a test to report. So this tracks the Python in SANDBOX_IMAGE —
# `skopeo inspect` it, or run `python -V` in a sandbox, when bumping that pin.
# uv downloads the interpreter, so the host need not have this version.
SANDBOX_PYTHON_VERSION="3.14"

# A standalone uv, so no system Python packaging tools are needed.
UV_VERSION="0.12.13"
UV_SHA256_X86_64="745765a3b6e360ad76743599ae5c42e9278c7edf8bbff9fc76d05bf2623a04dd"
UV_SHA256_AARCH64="2eaa5d94f5db7b3a1a092156b9420459e42ab0217d917fe74a876309cef9b5e9"

PYTHON_TEST_REQUIREMENTS=(
    "pytest==9.1.1"
    "pytest-asyncio==1.4.0"
    "pytest-xdist==3.8.0"
    "pyyaml==6.0.3"
    "anyio==4.15.1"
    "certifi==2026.7.22"
    "cloudpickle==3.1.2"
    "execnet==2.1.2"
    "grpcio==1.83.1"
    "h11==0.16.0"
    "httpcore==1.0.9"
    "httpx==0.28.1"
    "idna==3.19"
    "iniconfig==2.3.0"
    "packaging==26.3"
    "pluggy==1.6.0"
    "protobuf==7.36.1"
    "pygments==2.21.0"
    "typing-extensions==4.16.0"
)

# Tests that exercise policy, Landlock and inference and run against any
# driver. Left out: `transparent_tcp` (Docker/Podman driver networking only)
# and `live_policy_update`'s local override test (compiled for the Docker
# lane only).
DEFAULT_RUST_TESTS="landlock no_proxy live_policy_update proxy_egress_pipeline credential_gating host_gateway_alias forward_proxy_l7_bypass forward_proxy_graphql_l7 forward_proxy_jsonrpc_l7"
DEFAULT_PYTHON_TESTS="test_inference_routing.py test_sandbox_policy.py test_policy_validation.py test_sandbox_landlock.py"

RUST_TESTS="${UPSTREAM_E2E_RUST_TESTS:-$DEFAULT_RUST_TESTS}"
PYTHON_TESTS="${UPSTREAM_E2E_PYTHON_TESTS:-$DEFAULT_PYTHON_TESTS}"

# --- Layout ------------------------------------------------------------------

SOURCE_DIR="${CACHE_DIR}/openshell-src-${OPENSHELL_SOURCE_REV}"
E2E_TARGET_DIR="${CACHE_DIR}/upstream-e2e-target"
UV_DIR="${CACHE_DIR}/uv-${UV_VERSION}"
VENV_DIR="${CACHE_DIR}/upstream-e2e-venv-${OPENSHELL_SOURCE_REV}-py${SANDBOX_PYTHON_VERSION}"
SUITE_ARTIFACTS_DIR="${ARTIFACTS_DIR}/upstream-e2e"
SDK_GATEWAY_NAME="upstream-e2e"

require_e2e_tools() {
    local missing=()
    local tool
    for tool in podman python3; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        die "missing required tools: ${missing[*]}"
    fi
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
        || die "python3 >= 3.11 is required"
}

fetch_source() {
    [ -f "${SOURCE_DIR}/e2e/rust/Cargo.toml" ] && return
    log "fetching OpenShell source at v${OPENSHELL_VERSION} (${OPENSHELL_SOURCE_REV})"
    rm -rf "$SOURCE_DIR"
    fetch_git_rev "$SOURCE_DIR" "$OPENSHELL_REPO" "$OPENSHELL_SOURCE_REV"
    rm -rf "${SOURCE_DIR}/.git"
}

build_rust_tests() {
    log "building upstream Rust e2e tests"
    (
        cd "${SOURCE_DIR}/e2e/rust"
        RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" CARGO_TARGET_DIR="$E2E_TARGET_DIR" \
            cargo test --quiet --locked --features e2e-host-gateway --no-run </dev/null
    )
}

fetch_uv() {
    [ -x "${UV_DIR}/uv" ] && return
    local arch sha256
    case "$(uname -m)" in
        x86_64) arch="x86_64"; sha256="$UV_SHA256_X86_64" ;;
        aarch64) arch="aarch64"; sha256="$UV_SHA256_AARCH64" ;;
        *) die "unsupported architecture $(uname -m)" ;;
    esac
    local archive="uv-${arch}-unknown-linux-gnu.tar.gz"
    log "downloading uv ${UV_VERSION}"
    mkdir -p "$UV_DIR"
    curl -fsSL --retry 3 -o "${UV_DIR}/${archive}" \
        "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${archive}"
    echo "${sha256}  ${UV_DIR}/${archive}" | sha256sum --check --quiet \
        || die "checksum mismatch for ${archive}"
    tar -xzf "${UV_DIR}/${archive}" -C "$UV_DIR" --strip-components 1
    rm -f "${UV_DIR}/${archive}"
}

setup_python() {
    [ -x "${VENV_DIR}/bin/pytest" ] && return
    fetch_uv
    fetch_source

    log "creating Python test environment"
    rm -rf "$VENV_DIR"
    UV_CACHE_DIR="${CACHE_DIR}/uv-cache" "${UV_DIR}/uv" venv --quiet \
        --python "$SANDBOX_PYTHON_VERSION" "$VENV_DIR"
    UV_CACHE_DIR="${CACHE_DIR}/uv-cache" VIRTUAL_ENV="$VENV_DIR" \
        SETUPTOOLS_SCM_PRETEND_VERSION="$SDK_VERSION" \
        "${UV_DIR}/uv" pip install --quiet "$SOURCE_DIR" "${PYTHON_TEST_REQUIREMENTS[@]}"
}

# The CLI's gateway config and state stay in the work dir, as for the
# conformance runner. Data and cache do not: podman keeps its image store
# there, and the fixture image should survive between runs.
e2e_env() {
    env OPENSHELL_BIN="$CLI_BIN" \
        XDG_CONFIG_HOME="${WORK_DIR}/cli/config" \
        XDG_STATE_HOME="${WORK_DIR}/cli/state" \
        OPENSHELL_E2E_CONTAINER_ENGINE_UNSET_XDG_CONFIG_HOME=1 \
        CONTAINER_ENGINE=podman \
        "$@"
}

run_rust_test() {
    local test=$1
    (
        cd "${SOURCE_DIR}/e2e/rust"
        e2e_env OPENSHELL_GATEWAY_ENDPOINT="$(gateway_endpoint)" \
            RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" CARGO_TARGET_DIR="$E2E_TARGET_DIR" \
            cargo test --quiet --locked --features e2e-host-gateway --test "$test" \
            -- --test-threads=2 </dev/null
    )
}

run_python_tests() {
    # The SDK only connects through a gateway registered with the CLI.
    e2e_env "$CLI_BIN" gateway add "$(gateway_endpoint)" --local --name "$SDK_GATEWAY_NAME" \
        </dev/null >/dev/null
    local files=()
    local file
    for file in $PYTHON_TESTS; do
        files+=("$file")
    done
    (
        cd "${SOURCE_DIR}/e2e/python"
        e2e_env OPENSHELL_GATEWAY="$SDK_GATEWAY_NAME" \
            "${VENV_DIR}/bin/python" -m pytest "${files[@]}" \
            -p no:cacheprovider -o addopts="" -q -rfE \
            -n 3 --dist loadgroup \
            --junitxml "${SUITE_ARTIFACTS_DIR}/python.xml" </dev/null
    )
}

cmd_e2e() {
    [ "$#" -eq 0 ] || die "usage: $0 (takes no arguments; see scripts/openshell-env.sh to manage the environment)"
    require_tools
    require_e2e_tools
    ensure_not_running
    fetch_openshell
    fetch_source
    build_rust_tests
    setup_python

    env_up_for_suite
    mkdir -p "$SUITE_ARTIFACTS_DIR"
    echo "openshell source ${OPENSHELL_SOURCE_REV}" >"${SUITE_ARTIFACTS_DIR}/versions.txt"

    local failed=()
    local test
    for test in $RUST_TESTS; do
        log "running ${test}"
        if run_rust_test "$test" >"${SUITE_ARTIFACTS_DIR}/${test}.log" 2>&1; then
            log "${test}: $(grep -E '^test result' "${SUITE_ARTIFACTS_DIR}/${test}.log" | tail -n 1)"
        else
            log "${test}: FAILED (see ${SUITE_ARTIFACTS_DIR}/${test}.log)"
            grep -E '^test .* FAILED|panicked at' -A 4 "${SUITE_ARTIFACTS_DIR}/${test}.log" >&2 || true
            failed+=("$test")
        fi
    done

    if [ -n "$PYTHON_TESTS" ]; then
        log "running Python tests: ${PYTHON_TESTS}"
        if run_python_tests >"${SUITE_ARTIFACTS_DIR}/python.log" 2>&1; then
            log "python: $(tail -n 1 "${SUITE_ARTIFACTS_DIR}/python.log")"
        else
            log "python: FAILED (see ${SUITE_ARTIFACTS_DIR}/python.log)"
            grep -E '^(FAILED|ERROR)' "${SUITE_ARTIFACTS_DIR}/python.log" >&2 || true
            tail -n 1 "${SUITE_ARTIFACTS_DIR}/python.log" >&2 || true
            failed+=("python")
        fi
    fi

    if [ "${#failed[@]}" -gt 0 ]; then
        die "upstream e2e failed: ${failed[*]}; artifacts in ${ARTIFACTS_DIR}"
    fi
    log "all upstream e2e tests passed"
}

cmd_e2e "$@"
