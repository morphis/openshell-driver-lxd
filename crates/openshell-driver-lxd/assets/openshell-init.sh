#!/bin/sh
# SPDX-FileCopyrightText: 2026 Canonical Ltd.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Container-adapted init wrapper for OpenShell sandboxes.
#
# Runs as PID 1 inside an LXD container. Performs setup steps before
# exec-replacing itself with the openshell-sandbox supervisor so the
# supervisor becomes PID 1 (and handles zombie reaping by construction).

set -eu

ts() {
    printf "[container-init] %s\n" "$*"
}

# ---------------------------------------------------------------------------
# 1. Bring up loopback and eth0.
# ---------------------------------------------------------------------------
ip link set lo up 2>/dev/null || true
ip link set eth0 up 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Make sure /sandbox exists. An image that ships it keeps its own
#    ownership: the supervisor runs the workload as the image's sandbox user,
#    whose uid differs between images. One that lacks it gets it owned by that
#    user, when the image defines one.
# ---------------------------------------------------------------------------
if [ ! -d /sandbox ]; then
    mkdir -p /sandbox
    chmod 0755 /sandbox
    if _sandbox_uid=$(id -u sandbox 2>/dev/null) && _sandbox_gid=$(id -g sandbox 2>/dev/null); then
        chown "${_sandbox_uid}:${_sandbox_gid}" /sandbox 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# 3. Drop a dangling /etc/resolv.conf.
#
#    Ubuntu and Debian images often ship /etc/resolv.conf as a symlink to
#    systemd-resolved's stub, which doesn't exist when systemd is not PID 1.
#    Remove it; a nameserver is written once DHCP has configured eth0.
# ---------------------------------------------------------------------------
if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
fi

# ---------------------------------------------------------------------------
# 4. Bring up eth0 via DHCP.
#
#    Probe for image-provided DHCP clients (udhcpc, dhclient, dhcpcd) and
#    fall back to the driver-mounted udhcpc binary at /opt/openshell/net.
# ---------------------------------------------------------------------------
has_ipv4() {
    ip -4 addr show dev eth0 2>/dev/null | grep -q "inet "
}

if command -v udhcpc >/dev/null 2>&1; then
    # udhcpc: -i eth0, -f (foreground), -q (quit after lease), -n (exit on lease fail),
    # -t 10 -T 3 (10 attempts every 3 seconds = 30s bounded timeout)
    udhcpc -i eth0 -f -q -n -t 10 -T 3 || true
elif command -v dhclient >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
        timeout 30 dhclient -1 eth0 2>/dev/null || true
    else
        dhclient -1 eth0 2>/dev/null || true
    fi
elif command -v dhcpcd >/dev/null 2>&1; then
    dhcpcd -1 -t 30 eth0 2>/dev/null || true
elif [ -x /opt/openshell/net/udhcpc ]; then
    /opt/openshell/net/udhcpc -i eth0 -f -q -n -t 10 -T 3 -s /opt/openshell/net/udhcpc.script || true
else
    echo "openshell-init: no supported DHCP client found (udhcpc, dhclient, dhcpcd)" >&2
    exit 1
fi

waited=0
while ! has_ipv4 && [ "$waited" -lt 40 ]; do
    sleep 0.5
    waited=$((waited + 1))
done

if ! has_ipv4; then
    echo "openshell-init: timed out waiting for IPv4 address on eth0" >&2
    exit 1
fi

_eth0_addr=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}') || true
if [ -n "$_eth0_addr" ]; then
    ts "eth0 acquired IPv4: ${_eth0_addr}"
fi

# The DHCP client writes the name servers the network offers. Only if none
# were written, point resolv.conf at the network's gateway, which serves DNS on
# an LXD bridge (dnsmasq) though not on OVN. The gateway endpoint is not used:
# OpenShell's gateway may run anywhere and serves no DNS.
if [ ! -s /etc/resolv.conf ]; then
    _gw=$(ip route show default 2>/dev/null | awk '/^default/ { print $3; exit }') || true
    if [ -n "${_gw:-}" ]; then
        printf 'nameserver %s\n' "$_gw" > /etc/resolv.conf
    else
        printf 'nameserver 8.8.8.8\n' > /etc/resolv.conf
    fi
fi

# ---------------------------------------------------------------------------
# 5. Set container hostname from OPENSHELL_SANDBOX_ID.
# ---------------------------------------------------------------------------
if [ -n "${OPENSHELL_SANDBOX_ID:-}" ]; then
    hostname "${OPENSHELL_SANDBOX_ID}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 6. Source any injected environment file.
# ---------------------------------------------------------------------------
if [ -f /srv/openshell-env.sh ]; then
    # shellcheck source=/dev/null
    . /srv/openshell-env.sh
fi

# ---------------------------------------------------------------------------
# 7. Seed /etc/hosts with host.openshell.internal → the gateway's address.
#
#    The endpoint's host may be an IPv4 address, a bracketed IPv6 address or
#    a name; /etc/hosts needs an address, so a name is resolved first.
# ---------------------------------------------------------------------------
endpoint_host() {
    _ep="${OPENSHELL_ENDPOINT#*://}"
    _ep="${_ep%%/*}"
    case "$_ep" in
        \[*\]*)
            _ep="${_ep#\[}"
            printf '%s\n' "${_ep%%\]*}"
            ;;
        *)
            printf '%s\n' "${_ep%%:*}"
            ;;
    esac
}

is_ip_address() {
    case "$1" in
        "") return 1 ;;
        *:*) return 0 ;;
        *[!0-9.]*) return 1 ;;
        *) return 0 ;;
    esac
}

OPENSHELL_HOST_IP=""
if [ -n "${OPENSHELL_ENDPOINT:-}" ]; then
    _host=$(endpoint_host)
    if is_ip_address "$_host"; then
        OPENSHELL_HOST_IP="$_host"
    elif [ -n "$_host" ]; then
        OPENSHELL_HOST_IP=$(getent hosts "$_host" 2>/dev/null | awk '{ print $1; exit }') || true
        if [ -z "$OPENSHELL_HOST_IP" ]; then
            ts "WARN: cannot resolve gateway host ${_host}; host.openshell.internal not seeded"
        fi
    fi
else
    OPENSHELL_HOST_IP=$(ip route show default 2>/dev/null \
        | awk '/^default/ { print $3; exit }') || true
fi

if [ -n "$OPENSHELL_HOST_IP" ]; then
    sed -i '/host\.openshell\.internal/d' /etc/hosts 2>/dev/null || true
    printf '%s\t%s\n' "$OPENSHELL_HOST_IP" \
        "host.openshell.internal host.containers.internal host.docker.internal" \
        >> /etc/hosts
    ts "seeded /etc/hosts: host.openshell.internal → ${OPENSHELL_HOST_IP}"
elif [ -z "${OPENSHELL_ENDPOINT:-}" ]; then
    ts "WARN: could not determine host IP; host.openshell.internal not seeded"
fi

# ---------------------------------------------------------------------------
# 8. Probe OPENSHELL_ENDPOINT reachability before handing off to supervisor.
# ---------------------------------------------------------------------------
# An https gateway asks for the client certificate the supervisor presents, so
# the probe presents it too, and like the supervisor it verifies the
# certificate against OPENSHELL_GATEWAY_TLS_SERVER_NAME when that is set.
endpoint_port() {
    _ep="${OPENSHELL_ENDPOINT#*://}"
    _ep="${_ep%%/*}"
    _ep="${_ep##*\]}"
    case "$_ep" in
        *:*) printf '%s\n' "${_ep##*:}" ;;
        *) case "$OPENSHELL_ENDPOINT" in https://*) echo 443 ;; *) echo 80 ;; esac ;;
    esac
}

probe_endpoint() {
    if [ -n "${OPENSHELL_TLS_CA:-}" ]; then
        _url="${OPENSHELL_ENDPOINT}"
        set --
        if [ -n "${OPENSHELL_GATEWAY_TLS_SERVER_NAME:-}" ]; then
            _port=$(endpoint_port)
            _target=$(endpoint_host)
            case "$_target" in *:*) _target="[$_target]" ;; esac
            _name="${OPENSHELL_GATEWAY_TLS_SERVER_NAME}"
            case "$_name" in *:*) _name="[$_name]" ;; esac
            _url="https://${_name}:${_port}"
            set -- --connect-to "${_name}:${_port}:${_target}:${_port}"
        fi
        curl --silent --max-time 5 --output /dev/null --write-out "%{http_code}" \
            --cacert "${OPENSHELL_TLS_CA}" --cert "${OPENSHELL_TLS_CERT:-}" \
            --key "${OPENSHELL_TLS_KEY:-}" "$@" "$_url" 2>/dev/null
    else
        curl --silent --max-time 5 --output /dev/null --write-out "%{http_code}" \
            "${OPENSHELL_ENDPOINT}" 2>/dev/null
    fi
}

if [ -n "${OPENSHELL_ENDPOINT:-}" ] && command -v curl >/dev/null 2>&1; then
    _probe_result="unreachable"
    if probe_endpoint | grep -qE '^[1-9][0-9]{2}$'; then
        _probe_result="reachable"
    elif [ -n "$OPENSHELL_HOST_IP" ] && \
         curl --silent --max-time 5 --output /dev/null \
              "http://$(case "$OPENSHELL_HOST_IP" in *:*) printf '[%s]' "$OPENSHELL_HOST_IP" ;; *) printf '%s' "$OPENSHELL_HOST_IP" ;; esac)/" 2>/dev/null; then
        _probe_result="reachable (fallback)"
    fi
    ts "OPENSHELL_ENDPOINT probe: ${_probe_result} (${OPENSHELL_ENDPOINT})"
fi

# ---------------------------------------------------------------------------
# 9. Log token file status before handing off to the supervisor.
# ---------------------------------------------------------------------------
if [ -n "${OPENSHELL_SANDBOX_TOKEN_FILE:-}" ]; then
    if [ -f "${OPENSHELL_SANDBOX_TOKEN_FILE}" ] && [ -s "${OPENSHELL_SANDBOX_TOKEN_FILE}" ]; then
        _size=$(wc -c < "${OPENSHELL_SANDBOX_TOKEN_FILE}" 2>/dev/null || echo "?")
        ts "token file present: ${OPENSHELL_SANDBOX_TOKEN_FILE} (${_size} bytes)"
    elif [ -f "${OPENSHELL_SANDBOX_TOKEN_FILE}" ]; then
        ts "WARN: token file is empty: ${OPENSHELL_SANDBOX_TOKEN_FILE} — file push may have failed"
    else
        ts "WARN: token file missing: ${OPENSHELL_SANDBOX_TOKEN_FILE} — supervisor will fail to authenticate"
    fi
fi

# ---------------------------------------------------------------------------
# 10. Exec-replace this wrapper with the supervisor.
# ---------------------------------------------------------------------------
SUPERVISOR="/opt/openshell/bin/openshell-sandbox"

if [ ! -x "$SUPERVISOR" ]; then
    ts "FATAL: supervisor not found at ${SUPERVISOR}"
    exit 1
fi

LOADER=""
for _loader in \
    /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    /lib64/ld-linux-x86-64.so.2 \
    /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 \
    /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1 \
    /lib64/ld-linux-aarch64.so.1; do
    if [ -x "$_loader" ]; then
        LOADER="$_loader"
        break
    fi
done

LIB_PATH="/lib:/lib64:/usr/lib:/usr/lib64"
LIB_PATH="${LIB_PATH}:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu"
LIB_PATH="${LIB_PATH}:/lib/aarch64-linux-gnu:/usr/lib/aarch64-linux-gnu"

if [ -n "$LOADER" ]; then
    ts "exec: ${LOADER} --library-path ${LIB_PATH} ${SUPERVISOR} --workdir /sandbox $*"
    exec "$LOADER" --library-path "$LIB_PATH" "$SUPERVISOR" \
        --workdir /sandbox "$@"
else
    ts "WARN: no explicit loader found; falling back to direct exec"
    exec "$SUPERVISOR" --workdir /sandbox "$@"
fi

