#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Bootstraps a single-node MicroCloud with OVN, for hosts that have neither a
# spare disk nor a spare network interface — a CI runner, or a developer's
# laptop.
#
# From OpenShell v0.1.0 a sandbox cannot be created without an outer network
# fence, and LXD applies the per-NIC ACL that fence is made of only on OVN. So
# the driver's own tests, the conformance suite and the upstream e2e suite all
# need an OVN network, and a plain `lxd init` cannot provide one.
#
# MicroCloud normally wants a real disk for local storage and a spare NIC with
# no addresses for the OVN uplink. Neither exists on a runner, so both are
# synthesized:
#
#   storage  a sparse file attached to a loop device
#   uplink   one end of a veth pair; the other end sits in a host bridge that
#            carries the uplink gateway address and NATs onward, so sandboxes
#            reach the host and the internet as they would through a real
#            uplink
#
# Ceph is deliberately not installed: a single node has nothing to replicate
# to, and the driver only needs a pool to put root disks on.
#
# Usage: scripts/setup-ovn-test-env.sh [--purge [--yes]]
#
# --purge undoes all of the above. It is deliberately hard to fire by
# accident: it refuses while LXD holds any instance, it removes LXD only if
# this script installed it, and it wants a confirmation unless --yes (or
# OVN_TEST_PURGE_CONFIRM=1) says otherwise.
#
# Environment:
#   OVN_TEST_NETWORK   OVN network sandboxes go on (default: default, the one
#                      MicroCloud creates)
#   OVN_TEST_UPLINK_CIDR  uplink segment (default: 10.42.0.1/24)
#   OVN_TEST_DISK_SIZE    local storage file size (default: 30G)
#   LXD_CHANNEL / MICROOVN_CHANNEL / MICROCLOUD_CHANNEL  snap channels

set -euo pipefail

# MicroCloud's preseed creates this OVN network and points the default profile
# at it, which is also how rhea is laid out — so CI and a real MicroCloud look
# the same to the suites. Naming another one here would only add a moving part.
NETWORK="${OVN_TEST_NETWORK:-default}"
UPLINK_CIDR="${OVN_TEST_UPLINK_CIDR:-10.42.0.1/24}"
DISK_SIZE="${OVN_TEST_DISK_SIZE:-30G}"
LXD_CHANNEL="${LXD_CHANNEL:-6/stable}"
MICROOVN_CHANNEL="${MICROOVN_CHANNEL:-24.03/stable}"
# MicroCloud has no `latest` track; 3/stable is what rhea runs.
MICROCLOUD_CHANNEL="${MICROCLOUD_CHANNEL:-3/stable}"

# Names are prefixed so a purge can find them and so nothing collides with
# whatever else the host runs.
BRIDGE="osuplinkbr"
UPLINK_IFACE="osuplink0"
BRIDGE_PORT="osuplinkbr0"
DISK_IMAGE="/var/lib/openshell-test-local.img"
POOL="local"
# Written when this script installs LXD, so a purge can tell an LXD it
# brought into being from one that was already on the machine.
LXD_MARKER="/var/lib/openshell-test-env-installed-lxd"

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (the snaps, loop devices and bridge all need it)"

uplink_gateway() { echo "${UPLINK_CIDR%%/*}"; }
uplink_prefix() { echo "${UPLINK_CIDR##*/}"; }

# The OVN range has to sit on the uplink segment and outside anything the host
# hands out. Take the top of the /24 the gateway is in.
uplink_range() {
    local gw base
    gw="$(uplink_gateway)"
    base="${gw%.*}"
    echo "${base}.100-${base}.200"
}

# --- Purge -------------------------------------------------------------------

# Whether LXD currently holds any instance, in any project.
#
# Asked before removing it, because `snap remove --purge lxd` destroys every
# instance, image, profile and storage pool on the machine and leaves no
# snapshot to recover from. A developer's laptop and a CI runner take the same
# command; only one of them can afford it.
lxd_holds_instances() {
    command -v lxc >/dev/null 2>&1 || return 1
    [ -n "$(lxc list --all-projects --format csv -c n </dev/null 2>/dev/null)" ]
}

confirm_purge() {
    [ "${OVN_TEST_PURGE_CONFIRM:-}" = "1" ] && return 0
    [ "${1:-}" = "--yes" ] && return 0
    if [ ! -t 0 ]; then
        die "refusing to purge without a confirmation: pass --yes or set OVN_TEST_PURGE_CONFIRM=1"
    fi
    printf 'This removes MicroCloud, MicroOVN, the synthetic uplink' >&2
    if [ -f "$LXD_MARKER" ]; then
        printf ' and the LXD this script installed' >&2
    fi
    printf '.\nType "purge" to continue: ' >&2
    read -r reply
    [ "$reply" = "purge" ] || die "aborted"
}

purge() {
    confirm_purge "$@"

    if lxd_holds_instances; then
        lxc list --all-projects </dev/null >&2 || true
        die "LXD still holds instances; remove them first, or remove LXD yourself if you \
mean to lose them. This script will not do it for you."
    fi

    log "removing MicroCloud, MicroOVN and the synthetic uplink"
    snap remove --purge microcloud microovn 2>/dev/null || true

    # Only an LXD this script installed. `install_snaps` explicitly tolerates
    # a pre-existing one and merely refreshes it, so removing that would be
    # destroying something the script never created.
    if [ -f "$LXD_MARKER" ]; then
        log "removing the LXD this script installed"
        snap remove --purge lxd 2>/dev/null || true
        rm -f "$LXD_MARKER"
    else
        log "leaving LXD alone: this script did not install it"
    fi

    # Undo the forwarding and NAT create_uplink added. Without this the
    # MASQUERADE rule outlives the bridge and keeps translating anything that
    # later uses the same range, and the two ACCEPT rules stay at the top of
    # FORWARD.
    outbound="$(ip -4 route show default | awk '{print $5; exit}')" || true
    if [ -n "${outbound:-}" ]; then
        while iptables -t nat -C POSTROUTING -s "$(uplink_gateway)/$(uplink_prefix)" \
            -o "$outbound" -j MASQUERADE 2>/dev/null; do
            iptables -t nat -D POSTROUTING -s "$(uplink_gateway)/$(uplink_prefix)" \
                -o "$outbound" -j MASQUERADE
        done
    fi
    for direction in -i -o; do
        while iptables -C FORWARD "$direction" "$BRIDGE" -j ACCEPT 2>/dev/null; do
            iptables -D FORWARD "$direction" "$BRIDGE" -j ACCEPT
        done
    done

    ip link del "$UPLINK_IFACE" 2>/dev/null || true
    ip link del "$BRIDGE" 2>/dev/null || true
    if [ -f "$DISK_IMAGE" ]; then
        loop="$(losetup -j "$DISK_IMAGE" | cut -d: -f1)"
        [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
        rm -f "$DISK_IMAGE"
    fi
    log "purged"
}

# --- Synthetic hardware ------------------------------------------------------

# A bridge that holds the uplink gateway address and NATs onward, plus a veth
# whose far end is the "spare NIC" MicroCloud is given. MicroCloud refuses an
# interface that carries a global address, which is exactly why the address
# lives on the bridge and not on the interface it is handed.
create_uplink() {
    if ip link show "$UPLINK_IFACE" >/dev/null 2>&1; then
        log "uplink ${UPLINK_IFACE} already exists"
        return
    fi
    log "creating uplink ${UPLINK_IFACE} on ${BRIDGE} (${UPLINK_CIDR})"
    ip link add "$BRIDGE" type bridge
    ip addr add "$UPLINK_CIDR" dev "$BRIDGE"
    ip link set "$BRIDGE" up

    ip link add "$UPLINK_IFACE" type veth peer name "$BRIDGE_PORT"
    ip link set "$BRIDGE_PORT" master "$BRIDGE"
    ip link set "$BRIDGE_PORT" up
    # No address, and no autoconfiguration that could give it one: MicroCloud
    # checks.
    sysctl -qw "net.ipv6.conf.${UPLINK_IFACE}.disable_ipv6=1" || true
    ip link set "$UPLINK_IFACE" up

    # Sandboxes reach the gateway on the host and, for some e2e tests, the
    # internet. Both go through here.
    sysctl -qw net.ipv4.ip_forward=1
    local outbound
    outbound="$(ip -4 route show default | awk '{print $5; exit}')"
    [ -n "$outbound" ] || die "no default route; cannot NAT the uplink segment"
    iptables -t nat -C POSTROUTING -s "$(uplink_gateway)/$(uplink_prefix)" \
        -o "$outbound" -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -s "$(uplink_gateway)/$(uplink_prefix)" \
            -o "$outbound" -j MASQUERADE
    # LXD's own bridge rules default to DROP on FORWARD in some images.
    iptables -C FORWARD -i "$BRIDGE" -j ACCEPT 2>/dev/null ||
        iptables -I FORWARD 1 -i "$BRIDGE" -j ACCEPT
    iptables -C FORWARD -o "$BRIDGE" -j ACCEPT 2>/dev/null ||
        iptables -I FORWARD 1 -o "$BRIDGE" -j ACCEPT
}

create_disk() {
    local loop
    loop="$(losetup -j "$DISK_IMAGE" 2>/dev/null | cut -d: -f1)"
    if [ -n "$loop" ]; then
        log "local storage already attached at ${loop}"
        echo "$loop"
        return
    fi
    log "creating ${DISK_SIZE} local storage at ${DISK_IMAGE}"
    truncate -s "$DISK_SIZE" "$DISK_IMAGE"
    losetup -f --show "$DISK_IMAGE"
}

# --- MicroCloud --------------------------------------------------------------

install_snaps() {
    log "installing snaps (lxd=${LXD_CHANNEL} microovn=${MICROOVN_CHANNEL} microcloud=${MICROCLOUD_CHANNEL})"
    # LXD may already be installed on a runner image; a channel switch is a
    # refresh, not an install.
    if snap list lxd >/dev/null 2>&1; then
        snap refresh lxd --channel="$LXD_CHANNEL" --cohort="+" || true
    else
        snap install lxd --channel="$LXD_CHANNEL" --cohort="+"
        # Noted so --purge knows this LXD is the script's to remove.
        : >"$LXD_MARKER"
    fi
    snap list microovn >/dev/null 2>&1 || snap install microovn --channel="$MICROOVN_CHANNEL" --cohort="+"
    snap list microcloud >/dev/null 2>&1 || snap install microcloud --channel="$MICROCLOUD_CHANNEL" --cohort="+"
    # Nothing should move under a test run.
    snap refresh --hold lxd microovn microcloud >/dev/null
    snap list lxd microovn microcloud
}

bootstrap() {
    # MicroCloud refuses a second init outright, and a runner that re-runs this
    # (or a laptop) should get "already done", not a failure.
    if microcloud status >/dev/null 2>&1; then
        log "MicroCloud is already initialized"
        return
    fi
    local disk=$1 address
    address="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)"
    [ -n "$address" ] || die "cannot determine this host's address"

    local preseed=/root/openshell-microcloud-preseed.yaml
    cat >"$preseed" <<EOF
initiator_address: ${address}
systems:
- name: $(hostname -s)
  address: ${address}
  ovn_uplink_interface: ${UPLINK_IFACE}
  storage:
    local:
      path: ${disk}
      wipe: true
ovn:
  ipv4_gateway: ${UPLINK_CIDR}
  ipv4_range: $(uplink_range)
  dns_servers: 1.1.1.1
EOF
    log "MicroCloud preseed:"
    sed 's/^/    /' "$preseed" >&2
    microcloud preseed <"$preseed"
}

# The suites read where sandboxes go from the `default` profile, so this makes
# sure it names an OVN network and a pool. MicroCloud normally leaves it that
# way already; this is here so a host it did not, or one where
# `OVN_TEST_NETWORK` names something else, still works.
configure_profile() {
    lxc network show "$NETWORK" </dev/null >/dev/null 2>&1 ||
        die "network ${NETWORK} does not exist; MicroCloud should have created it"
    # From the CSV listing rather than from `lxc query`, whose pretty-printed
    # JSON is not something to pick apart with a regex.
    local type
    type="$(lxc network list --format csv -c nt </dev/null |
        awk -F, -v n="$NETWORK" '$1 == n { print $2 }')"
    [ "$type" = "ovn" ] ||
        die "network ${NETWORK} is a '${type}' network, and sandboxes need OVN"

    if [ "$(lxc profile device get default eth0 network </dev/null 2>/dev/null || true)" != "$NETWORK" ]; then
        log "pointing the default profile's eth0 at ${NETWORK}"
        lxc profile device remove default eth0 </dev/null >/dev/null 2>&1 || true
        lxc profile device add default eth0 nic network="$NETWORK" name=eth0 </dev/null >/dev/null
    fi
    if [ -z "$(lxc profile device get default root pool </dev/null 2>/dev/null || true)" ]; then
        log "giving the default profile a root disk on ${POOL}"
        lxc profile device remove default root </dev/null >/dev/null 2>&1 || true
        lxc profile device add default root disk path=/ pool="$POOL" </dev/null >/dev/null
    fi
    log "sandboxes go on ${NETWORK} (${type}), root disks on ${POOL}"
}

verify() {
    log "verifying the OVN network carries traffic"
    local name="osovn-verify-$$"
    lxc launch ubuntu-minimal:24.04 "$name" </dev/null >/dev/null
    # shellcheck disable=SC2064
    trap "lxc delete --force '$name' </dev/null >/dev/null 2>&1 || true" RETURN

    local address=""
    for _ in $(seq 1 60); do
        address="$(lxc list "$name" -c 4 --format csv </dev/null | awk '{print $1}')"
        [ -n "$address" ] && break
        sleep 2
    done
    [ -n "$address" ] || die "instance on ${NETWORK} never got an address"
    log "instance address: ${address}"

    lxc exec "$name" -- getent hosts archive.ubuntu.com >/dev/null ||
        die "instance on ${NETWORK} cannot resolve DNS"
    lxc exec "$name" -- curl -fsS -o /dev/null -m 20 https://archive.ubuntu.com/ ||
        die "instance on ${NETWORK} cannot reach the internet"

    # The fence itself: a per-NIC ACL, which is the whole reason for OVN.
    lxc network acl create "${name}-acl" </dev/null >/dev/null
    lxc config device override "$name" eth0 \
        security.acls="${name}-acl" \
        security.acls.default.egress.action=reject \
        security.acls.default.ingress.action=reject </dev/null >/dev/null ||
        die "${NETWORK} cannot carry a per-NIC ACL, which is what sandboxes need it for"
    lxc network acl delete "${name}-acl" </dev/null >/dev/null 2>&1 || true
    log "OVN network ${NETWORK} is usable: address, DNS, egress and a per-NIC ACL"
}

# --- Main --------------------------------------------------------------------

case "${1:-}" in
    --purge) purge "${2:-}"; exit 0 ;;
    "") ;;
    *) die "usage: $0 [--purge [--yes]]" ;;
esac

install_snaps
create_uplink
disk="$(create_disk)"
bootstrap "$disk"
configure_profile
verify
log "done; sandboxes go on ${NETWORK} (pool ${POOL})"
