#!/opt/openshell/net/busybox sh
# SPDX-FileCopyrightText: 2026 Canonical Ltd.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Container-adapted init wrapper for OpenShell sandboxes.
#
# Runs as PID 1 inside an LXD container. Performs setup steps before
# exec-replacing itself with the sandbox boundary (workload half) or the
# supervisor companion (trusted half).
#
# Everything this script runs on the workload half comes from the driver's own
# read-only volumes, by absolute path — the interpreter in the shebang above
# included. That is deliberate. This script is PID 1 and therefore root inside
# the container, and the workload half's rootfs is the user's own image: a
# program taken from it would run as root before the boundary has dropped
# privilege, and could replace the drop, or the boundary, with anything. LXD
# has no "init command" instance option to exec the boundary directly the way
# Podman's `entrypoint` does, so naming every program explicitly is how the
# same guarantee is reached here.
#
# The supervisor companion's rootfs is the driver's own supervisor image, not
# the user's, so its half may use what that image ships.

set -eu

# The driver's volumes. `build_create_devices` and `build_supervisor_devices`
# mount both on every instance, so a missing one is a bug, not a
# configuration: the script says so rather than falling back to the image.
BUSYBOX=/opt/openshell/net/busybox
DHCP_CLIENT=/opt/openshell/net/udhcpc
DHCP_SCRIPT=/opt/openshell/net/udhcpc.script
BOUNDARY=/opt/openshell/bin/openshell-sandbox

RUNTIME_DIR="/etc/openshell/runtime"
# The boundary's own files live apart from the trusted side's, in a directory
# the boundary owns: it deletes its one-use bootstrap after reading it.
BOUNDARY_DIR="/etc/openshell/boundary"

ts() {
    printf "[container-init] %s\n" "$*"
}

if [ ! -x "$BUSYBOX" ]; then
    echo "openshell-init: ${BUSYBOX} is missing; the DHCP-client volume did not mount" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Bring up loopback and eth0.
# ---------------------------------------------------------------------------
"$BUSYBOX" ip link set lo up 2>/dev/null || true
"$BUSYBOX" ip link set eth0 up 2>/dev/null || true

# ---------------------------------------------------------------------------
# 2. Make sure /sandbox exists.
#
#    /sandbox is the sandbox's working directory, so the workload has to be
#    able to write it. On the workload half the boundary's own
#    `launch-capability-free` gives it to the resolved identity, while it is
#    still root and before it reads anything — so the ownership is applied by
#    the driver's binary rather than by an image-supplied `chown`, and an
#    image that ships /sandbox itself no longer keeps a workdir its workload
#    cannot write.
#
#    A symlink is refused outright. `launch-capability-free` refuses one too;
#    saying so here makes the reason legible in the console log.
# ---------------------------------------------------------------------------
if [ -L /sandbox ]; then
    ts "FATAL: /sandbox is a symlink; the sandbox workspace must be a real directory"
    exit 1
fi
if [ ! -d /sandbox ]; then
    "$BUSYBOX" mkdir -p /sandbox
    "$BUSYBOX" chmod 0755 /sandbox
fi

# ---------------------------------------------------------------------------
# 3. Drop a dangling /etc/resolv.conf.
#
#    Ubuntu and Debian images often ship /etc/resolv.conf as a symlink to
#    systemd-resolved's stub, which doesn't exist when systemd is not PID 1.
#    Remove it; a nameserver is written once DHCP has configured eth0.
# ---------------------------------------------------------------------------
if [ -L /etc/resolv.conf ]; then
    "$BUSYBOX" rm -f /etc/resolv.conf
fi

# The writes below land in the image's own /etc, and an image may ship any of
# these paths as a symlink pointing at something the driver staged. Writing
# through one would truncate that file as root, before the boundary reads it.
for _guarded in /etc/resolv.conf /etc/resolv.conf.dhcp /etc/hosts; do
    if [ -L "$_guarded" ]; then
        "$BUSYBOX" rm -f "$_guarded"
    fi
done

# ---------------------------------------------------------------------------
# 4. Bring up eth0 via DHCP, with the driver's own client.
#
#    The image is not probed for a DHCP client any more. It used to be
#    probed first, which handed an image the easiest way there is to run its
#    own program as root in its own container before the boundary starts.
# ---------------------------------------------------------------------------
has_ipv4() {
    "$BUSYBOX" ip -4 addr show dev eth0 2>/dev/null | "$BUSYBOX" grep -q "inet "
}

if [ ! -x "$DHCP_CLIENT" ]; then
    ts "FATAL: ${DHCP_CLIENT} is missing; the DHCP-client volume did not mount"
    exit 1
fi

# udhcpc: -i eth0, -f (foreground), -q (quit after lease), -n (exit on lease
# fail), -t 10 -T 3 (10 attempts every 3 seconds = 30s bounded timeout)
"$DHCP_CLIENT" -i eth0 -f -q -n -t 10 -T 3 -s "$DHCP_SCRIPT" || true

waited=0
while ! has_ipv4 && [ "$waited" -lt 40 ]; do
    "$BUSYBOX" sleep 0.5
    waited=$((waited + 1))
done

if ! has_ipv4; then
    ts "FATAL: timed out waiting for IPv4 address on eth0"
    exit 1
fi

# shellcheck disable=SC2016  # $4 is awk's field, not a shell expansion
_eth0_addr=$("$BUSYBOX" ip -4 -o addr show eth0 2>/dev/null | "$BUSYBOX" awk '{print $4}') || true
if [ -n "$_eth0_addr" ]; then
    ts "eth0 acquired IPv4: ${_eth0_addr}"
fi

# The DHCP client writes the name servers the network offers. Only if none
# were written, point resolv.conf at the network's gateway, which serves DNS on
# an LXD bridge (dnsmasq) though not on OVN. The gateway endpoint is not used:
# OpenShell's gateway may run anywhere and serves no DNS.
#
# There is deliberately no public-resolver fallback. A sandbox that silently
# resolved through someone else's resolver would leak every name it looks up,
# and in an air-gapped or egress-restricted deployment it would fail later and
# less legibly than a warning here.
if [ ! -s /etc/resolv.conf ]; then
    # shellcheck disable=SC2016  # $3 is awk's field, not a shell expansion
    _gw=$("$BUSYBOX" ip route show default 2>/dev/null |
        "$BUSYBOX" awk '/^default/ { print $3; exit }') || true
    if [ -n "${_gw:-}" ]; then
        printf 'nameserver %s\n' "$_gw" > /etc/resolv.conf
    else
        ts "WARN: no nameserver from DHCP and no default gateway; DNS is unconfigured"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Set container hostname from OPENSHELL_SANDBOX_ID.
# ---------------------------------------------------------------------------
if [ -n "${OPENSHELL_SANDBOX_ID:-}" ]; then
    "$BUSYBOX" hostname "${OPENSHELL_SANDBOX_ID}" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 6. Seed /etc/hosts with host.openshell.internal → the gateway's address.
#
#    The endpoint's host may be an IPv4 address, a bracketed IPv6 address or
#    a name; /etc/hosts needs an address, so a name is resolved first.
#
#    Only the companion is given OPENSHELL_ENDPOINT — the workload boundary
#    takes everything from its bootstrap — so the name-resolution branch
#    below, which needs a `getent` from the rootfs, is only ever reached on
#    the half whose rootfs is the driver's own. A loopback name never gets
#    that far: it is answered without asking either /etc/hosts or DNS, since
#    neither has to know it.
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
        # A loopback name is answered here rather than resolved. RFC 6761
        # makes it a special-use name no DNS resolver has to answer, and the
        # rootfs may be of no help either: the default sandbox image ships an
        # empty /etc/hosts, so the files module of a getent finds nothing and
        # the question goes to DNS, and upstream's pinned supervisor image
        # ships no getent at all.
        case "$_host" in
            localhost|localhost.localdomain)
                OPENSHELL_HOST_IP="127.0.0.1"
                ;;
            ip6-localhost|ip6-loopback)
                OPENSHELL_HOST_IP="::1"
                ;;
            *)
                # shellcheck disable=SC2016  # $1 is awk's field, not a shell expansion
                OPENSHELL_HOST_IP=$(getent hosts "$_host" 2>/dev/null | "$BUSYBOX" awk '{ print $1; exit }') || true
                if [ -z "$OPENSHELL_HOST_IP" ]; then
                    ts "WARN: cannot resolve gateway host ${_host}; host.openshell.internal not seeded"
                fi
                ;;
        esac
    fi
else
    # shellcheck disable=SC2016  # $3 is awk's field, not a shell expansion
    OPENSHELL_HOST_IP=$("$BUSYBOX" ip route show default 2>/dev/null |
        "$BUSYBOX" awk '/^default/ { print $3; exit }') || true
fi

if [ -n "$OPENSHELL_HOST_IP" ]; then
    "$BUSYBOX" sed -i '/host\.openshell\.internal/d' /etc/hosts 2>/dev/null || true
    printf '%s\t%s\n' "$OPENSHELL_HOST_IP" \
        "host.openshell.internal host.containers.internal host.docker.internal" \
        >> /etc/hosts
    ts "seeded /etc/hosts: host.openshell.internal → ${OPENSHELL_HOST_IP}"
elif [ -z "${OPENSHELL_ENDPOINT:-}" ]; then
    ts "WARN: could not determine host IP; host.openshell.internal not seeded"
fi

# ---------------------------------------------------------------------------
# 7. Hand over to the workload boundary.
#
#    The boundary is the driver's own statically linked binary, and it drops
#    privilege itself: `launch-capability-free` chowns the workspace, empties
#    every capability set, sets no_new_privs, changes all three uid and gid
#    triples so root cannot be regained, and only then reads the bootstrap.
#    Upstream's Podman driver launches the same subcommand the same way.
#
#    This replaces an earlier `setpriv --reuid ... openshell-sandbox
#    --bootstrap`, which resolved `setpriv` — and, for a dynamically linked
#    boundary, the loader and every library — from the user's own image. A
#    `setpriv` of the image's choosing could drop to the right identity and
#    exec something else entirely, and that something would then answer the
#    Sandbox Protocol and report whatever confinement it liked.
#
#    openshell-sandbox has no --workdir: the workload's working directory
#    comes from the bootstrap's identity.
# ---------------------------------------------------------------------------
if [ "${OPENSHELL_ROLE:-}" != "supervisor" ]; then
    if [ ! -x "$BOUNDARY" ]; then
        ts "FATAL: ${BOUNDARY} is missing; the boundary volume did not mount"
        exit 1
    fi
    if [ ! -f "${BOUNDARY_DIR}/bootstrap.json" ]; then
        ts "FATAL: ${BOUNDARY_DIR}/bootstrap.json is missing"
        exit 1
    fi

    _identity_file="${RUNTIME_DIR}/workload-identity"
    if [ ! -f "$_identity_file" ]; then
        ts "FATAL: ${_identity_file} is missing; cannot determine the workload identity"
        exit 1
    fi
    read -r _uid _gid _ < "$_identity_file"
    if [ -z "${_uid:-}" ] || [ -z "${_gid:-}" ] || [ "$_uid" = "0" ] || [ "$_gid" = "0" ]; then
        ts "FATAL: workload identity '${_uid:-}:${_gid:-}' is unusable; it must be non-root"
        exit 1
    fi

    # The boundary runs a DNS relay on 127.0.0.53:53 as an unprivileged user
    # with no capabilities, so it requires unprivileged low-port binds. LXD
    # rejects linux.sysctl.* on an unprivileged container, but this init is
    # root inside the container's own network namespace, where the knob is
    # namespaced and writable. Upstream's Podman driver sets the same sysctl
    # to the same value on its workload container.
    _port_start=/proc/sys/net/ipv4/ip_unprivileged_port_start
    if ! echo 0 > "$_port_start" 2>/dev/null; then
        ts "FATAL: cannot set net.ipv4.ip_unprivileged_port_start=0; the sandbox \
boundary cannot bind its DNS relay without it"
        exit 1
    fi

    ts "exec: ${BOUNDARY} launch-capability-free ${_uid} ${_gid} (workspace /sandbox)"
    exec "$BOUNDARY" launch-capability-free \
        "$_uid" "$_gid" "${BOUNDARY_DIR}/bootstrap.json" /sandbox
fi

# ---------------------------------------------------------------------------
# 8. Supervisor companion: probe the gateway, then hand over.
#
#    Everything below runs only on the trusted half, whose rootfs is the
#    driver's own supervisor image — so it may use what that image ships,
#    including curl and the dynamic loader.
# ---------------------------------------------------------------------------
if [ -f /srv/openshell-env.sh ]; then
    # shellcheck source=/dev/null
    . /srv/openshell-env.sh
fi

endpoint_port() {
    _ep="${OPENSHELL_ENDPOINT#*://}"
    _ep="${_ep%%/*}"
    _ep="${_ep##*\]}"
    case "$_ep" in
        *:*) printf '%s\n' "${_ep##*:}" ;;
        *) case "$OPENSHELL_ENDPOINT" in https://*) echo 443 ;; *) echo 80 ;; esac ;;
    esac
}

# An https gateway asks for the client certificate the supervisor presents, so
# the probe presents it too, and like the supervisor it verifies the
# certificate against OPENSHELL_GATEWAY_TLS_SERVER_NAME when that is set.
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
    if probe_endpoint | "$BUSYBOX" grep -qE '^[1-9][0-9]{2}$'; then
        _probe_result="reachable"
    elif [ -n "$OPENSHELL_HOST_IP" ] && \
         curl --silent --max-time 5 --output /dev/null \
              "http://$(case "$OPENSHELL_HOST_IP" in *:*) printf '[%s]' "$OPENSHELL_HOST_IP" ;; *) printf '%s' "$OPENSHELL_HOST_IP" ;; esac)/" 2>/dev/null; then
        _probe_result="reachable (fallback)"
    fi
    ts "OPENSHELL_ENDPOINT probe: ${_probe_result} (${OPENSHELL_ENDPOINT})"
fi

# The companion's own rootfs ships the supervisor. The driver-mounted binary
# is the last resort: it is the workload boundary binary, staged under its own
# name, so falling through to it means the supervisor image did not carry a
# supervisor.
SUPERVISOR=""
for _candidate in \
    /openshell-supervisor \
    /opt/openshell/bin/openshell-supervisor \
    /usr/bin/openshell-supervisor \
    "$BOUNDARY"; do
    if [ -x "$_candidate" ]; then
        SUPERVISOR="$_candidate"
        break
    fi
done
if [ -z "$SUPERVISOR" ]; then
    ts "FATAL: supervisor not found"
    exit 1
fi

if [ ! -f "${RUNTIME_DIR}/backend-descriptor.json" ]; then
    ts "FATAL: ${RUNTIME_DIR}/backend-descriptor.json is missing"
    exit 1
fi
if [ ! -f "${RUNTIME_DIR}/auth-bundle.json" ]; then
    ts "FATAL: ${RUNTIME_DIR}/auth-bundle.json is missing"
    exit 1
fi
EXTRA_ARGS="--backend-descriptor-file ${RUNTIME_DIR}/backend-descriptor.json"
EXTRA_ARGS="${EXTRA_ARGS} --auth-bundle-file ${RUNTIME_DIR}/auth-bundle.json"

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

# A statically linked binary needs no loader, and passing one to it fails.
if [ -n "$LOADER" ] && ldd "$SUPERVISOR" 2>/dev/null | "$BUSYBOX" grep -q "=>"; then
    ts "exec: ${LOADER} --library-path ${LIB_PATH} ${SUPERVISOR} --workdir /sandbox ${EXTRA_ARGS} $*"
    # shellcheck disable=SC2086
    exec "$LOADER" --library-path "$LIB_PATH" "$SUPERVISOR" \
        --workdir /sandbox ${EXTRA_ARGS} "$@"
else
    ts "exec: ${SUPERVISOR} --workdir /sandbox ${EXTRA_ARGS} $*"
    # shellcheck disable=SC2086
    exec "$SUPERVISOR" --workdir /sandbox ${EXTRA_ARGS} "$@"
fi
