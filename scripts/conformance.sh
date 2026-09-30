#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runs upstream OpenShell's conformance suite (`openshell-conformance`)
# against an OpenShell gateway backed by this driver, in the environment
# scripts/openshell-env.sh provides:
#
#   smoke              create, inspect, exec in, delete a base sandbox
#   sandbox-lifecycle  sandbox stop, start and deletion behaviour
#
# `openshell-conformance list` is the authority on what exists; these are what
# v0.1.2 registers. The runner is not released, so it is built from the
# same pinned revision as everything else it drives.
#
# Usage: scripts/conformance.sh
#
# Environment (in addition to the OPENSHELL_TEST_* variables):
#   CONFORMANCE_SCENARIOS  space-separated scenarios (default: "smoke sandbox-lifecycle")

set -euo pipefail

# shellcheck source=scripts/openshell-env.sh
. "$(dirname "${BASH_SOURCE[0]}")/openshell-env.sh"

# The conformance CLI comes from the same revision as everything else it
# drives. It used to be pinned separately: `openshell-conformance` appeared
# after v0.0.116, so it had to be newer than the release under test, and then
# no newer than the last revision the v0.0.116 CLI could still drive. Building
# the gateway and CLI from source removes that squeeze — there is one revision
# now, and it is the one the driver targets.
CONFORMANCE_REV="${OPENSHELL_SOURCE_REV}"

SCENARIOS="${CONFORMANCE_SCENARIOS:-smoke sandbox-lifecycle}"
CONFORMANCE_BIN="${CACHE_DIR}/conformance-${CONFORMANCE_REV}/bin/openshell-conformance"
SUITE_ARTIFACTS_DIR="${ARTIFACTS_DIR}/conformance"

build_conformance() {
    [ -x "$CONFORMANCE_BIN" ] && return
    local src="${CACHE_DIR}/conformance-src"
    log "building openshell-conformance at ${CONFORMANCE_REV}"
    rm -rf "$src"
    fetch_git_rev "$src" "$OPENSHELL_REPO" "$CONFORMANCE_REV"
    # Upstream pins its own toolchain; the runner builds with ours, so a
    # rustup-managed cargo does not download a second toolchain for it.
    RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}" cargo install --quiet --locked \
        --path "${src}/crates/openshell-conformance-cli" \
        --root "${CACHE_DIR}/conformance-${CONFORMANCE_REV}"
    rm -rf "$src"
}

[ "$#" -eq 0 ] || die "usage: $0 (takes no arguments; see scripts/openshell-env.sh to manage the environment)"

require_tools
fetch_openshell
build_conformance

env_up_for_suite
mkdir -p "$SUITE_ARTIFACTS_DIR"
echo "conformance ${CONFORMANCE_REV}" >"${SUITE_ARTIFACTS_DIR}/versions.txt"

# One scenario per invocation, so a failure names itself and one scenario's
# leftovers cannot confuse the next.
failed=()
for scenario in $SCENARIOS; do
    log "running ${scenario}"
    if cli_env "$CONFORMANCE_BIN" run \
        --openshell-bin "$CLI_BIN" \
        --output json \
        "$scenario" \
        </dev/null >"${SUITE_ARTIFACTS_DIR}/${scenario}.json" 2>"${SUITE_ARTIFACTS_DIR}/${scenario}.log"; then
        log "${scenario}: passed"
    else
        log "${scenario}: FAILED (see ${SUITE_ARTIFACTS_DIR}/${scenario}.json)"
        cat "${SUITE_ARTIFACTS_DIR}/${scenario}.json" >&2 || true
        cat "${SUITE_ARTIFACTS_DIR}/${scenario}.log" >&2 || true
        failed+=("$scenario")
    fi
done

if [ "${#failed[@]}" -gt 0 ]; then
    die "conformance failed: ${failed[*]}; artifacts in ${ARTIFACTS_DIR}"
fi
log "all conformance scenarios passed"
