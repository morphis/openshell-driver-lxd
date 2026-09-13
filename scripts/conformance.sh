#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs upstream OpenShell's conformance suite (`openshell-conformance`)
# against an OpenShell gateway backed by this driver, in the environment
# scripts/openshell-env.sh provides:
#
#   smoke               create, Ready, list, exec, delete
#   sandbox-continuity  a running sandbox keeps its workload and a stopped one
#                       stays stopped across a gateway and a driver restart
#
# The conformance runner is not released; it is built from the newest
# upstream revision whose CLI usage the pinned OpenShell CLI supports.
#
# Usage: scripts/conformance.sh
#
# Environment (in addition to the OPENSHELL_TEST_* variables):
#   CONFORMANCE_SCENARIOS  space-separated scenarios (default: "smoke sandbox-continuity")

set -euo pipefail

# shellcheck source=scripts/openshell-env.sh
. "$(dirname "${BASH_SOURCE[0]}")/openshell-env.sh"

# `openshell-conformance` first appeared after v0.0.116. The next upstream
# change to it (33bbda3) moved `sandbox list` to `--page-size`, which the
# v0.0.116 CLI does not have, so this is the newest revision it can drive.
CONFORMANCE_REV="ddc8bba9677ed8413849c8f148364df2f0146a6d"

SCENARIOS="${CONFORMANCE_SCENARIOS:-smoke sandbox-continuity}"
CONFORMANCE_BIN="${CACHE_DIR}/conformance-${CONFORMANCE_REV}/bin/openshell-conformance"
SUITE_ARTIFACTS_DIR="${ARTIFACTS_DIR}/conformance"
PLANS_DIR="${WORK_DIR}/conformance"

build_conformance() {
    [ -x "$CONFORMANCE_BIN" ] && return
    local src="${CACHE_DIR}/conformance-src"
    log "building openshell-conformance at ${CONFORMANCE_REV}"
    rm -rf "$src"
    mkdir -p "$src"
    git -C "$src" init --quiet
    git -C "$src" fetch --quiet --depth 1 "$OPENSHELL_REPO" "$CONFORMANCE_REV"
    git -C "$src" checkout --quiet FETCH_HEAD
    # Upstream pins its own toolchain; the runner builds with ours, so a
    # rustup-managed cargo does not download a second toolchain for it.
    RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" cargo install --quiet --locked \
        --path "${src}/crates/openshell-conformance-cli" \
        --root "${CACHE_DIR}/conformance-${CONFORMANCE_REV}"
    rm -rf "$src"
}

write_plans() {
    mkdir -p "$PLANS_DIR"
    local restart_gateway restart_driver
    restart_gateway="$(write_host_action restart-gateway)"
    restart_driver="$(write_host_action restart-driver)"

    cat >"${PLANS_DIR}/smoke.toml" <<EOF
version = 1

[[runs]]
scenario = "smoke"
EOF

    cat >"${PLANS_DIR}/sandbox-continuity.toml" <<EOF
version = 1

[[runs]]
scenario = "sandbox-continuity"
workload_expectation = "reconciled"

[[runs.actions]]
name = "gateway-restart"
command = '${restart_gateway}'
timeout_secs = 120

[[runs.actions]]
name = "driver-restart"
command = '${restart_driver}'
timeout_secs = 120
EOF
}

[ "$#" -eq 0 ] || die "usage: $0 (takes no arguments; see scripts/openshell-env.sh to manage the environment)"

require_tools
fetch_openshell
build_conformance

env_up_for_suite
write_plans
mkdir -p "$SUITE_ARTIFACTS_DIR"
cp "${PLANS_DIR}"/*.toml "$SUITE_ARTIFACTS_DIR/"
echo "conformance ${CONFORMANCE_REV}" >"${SUITE_ARTIFACTS_DIR}/versions.txt"

failed=()
for scenario in $SCENARIOS; do
    log "running ${scenario}"
    if cli_env "$CONFORMANCE_BIN" run \
        --openshell-bin "$CLI_BIN" \
        --plan "${PLANS_DIR}/${scenario}.toml" \
        --output json \
        </dev/null >"${SUITE_ARTIFACTS_DIR}/${scenario}.json" 2>"${SUITE_ARTIFACTS_DIR}/${scenario}.log"; then
        log "${scenario}: passed"
    else
        log "${scenario}: FAILED (see ${SUITE_ARTIFACTS_DIR}/${scenario}.json)"
        cat "${SUITE_ARTIFACTS_DIR}/${scenario}.json" >&2 || true
        failed+=("$scenario")
    fi
done

if [ "${#failed[@]}" -gt 0 ]; then
    die "conformance failed: ${failed[*]}; artifacts in ${ARTIFACTS_DIR}"
fi
log "all conformance scenarios passed"
