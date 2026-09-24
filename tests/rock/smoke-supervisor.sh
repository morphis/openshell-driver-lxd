#!/usr/bin/env bash
# Smoke test for the openshell-supervisor rock.
# Invoked by the CI build job after rockcraft-pack.
#
# Unlike the sandbox rock, this image is *run*: the driver converts it into an
# LXD image and boots the companion container from it, after replacing its init
# with the driver's own shell script. So the checks here are about it being a
# usable rootfs — the binary, and the handful of programs that script needs —
# rather than about it containing nothing else.
set -euo pipefail

ROCK_DIR="${ROCK_DIR:-rocks/supervisor}"
IMAGE="openshell-supervisor:test"
BINARY="openshell-supervisor"

# ---------------------------------------------------------------------------
# Guard: Docker daemon must be available to the current user (no sudo).
# ---------------------------------------------------------------------------
docker info > /dev/null 2>&1 \
  || { echo "ERROR: Docker daemon is not available to the current user — smoke test requires docker (ensure the user is in the 'docker' group or Docker is rootless)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Locate packed rock and load it into the local Docker daemon.
# ---------------------------------------------------------------------------
ROCK_FILE=$(find "${ROCK_DIR}" -maxdepth 1 -name "*.rock" | head -1)
if [[ -z "${ROCK_FILE}" ]]; then
  echo "ERROR: no .rock file found in ${ROCK_DIR}" >&2
  exit 1
fi
echo "Using rock: ${ROCK_FILE}"

SKOPEO=$(command -v skopeo 2>/dev/null || echo /snap/bin/rockcraft.skopeo)
echo "Using skopeo: ${SKOPEO}"
# --insecure-policy is required because the rockcraft.skopeo snap does not ship
# a default /etc/containers/policy.json. We are copying a locally-built OCI
# archive into the local Docker daemon, so signature policy enforcement is not
# applicable here.
"${SKOPEO}" copy --insecure-policy "oci-archive:${ROCK_FILE}" "docker-daemon:${IMAGE}"

run() {
  docker run --rm --entrypoint "$1" "${IMAGE}" "${@:2}"
}

# ---------------------------------------------------------------------------
# 1. The supervisor binary is at the image root and runs.
#
#    `--version` is the cheapest thing it will do without a descriptor or an
#    auth bundle, both of which it otherwise refuses to start without.
# ---------------------------------------------------------------------------
echo "==> Check: /${BINARY} runs"
VERSION=$(run "/${BINARY}" --version)
echo "    ${VERSION}"
[[ -n "${VERSION}" ]] \
  || { echo "ERROR: /${BINARY} printed no version" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2. It refuses to start without its RFC 0012 inputs, which is what tells us
#    this is a v0.1.0 supervisor and not an older combined one. A combined
#    supervisor accepts an empty argument list and starts supervising.
# ---------------------------------------------------------------------------
echo "==> Check: ${BINARY} takes the RFC 0012 inputs"
HELP=$(run "/${BINARY}" --help)
for FLAG in --backend-descriptor-file --auth-bundle-file; do
  grep -q -- "${FLAG}" <<<"${HELP}" \
    || { echo "ERROR: ${BINARY} does not accept ${FLAG}; this is not an RFC 0012 supervisor" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# 3. The programs the driver's init script needs before the supervisor runs.
#    Upstream's released supervisor image is distroless and has none of them,
#    which is the reason this rock exists.
# ---------------------------------------------------------------------------
echo "==> Check: the init script's dependencies are present"
for PROGRAM in /bin/sh /usr/bin/getent /usr/bin/curl; do
  run /bin/sh -c "test -x ${PROGRAM}" \
    || { echo "ERROR: ${PROGRAM} is missing; the driver's init script needs it" >&2; exit 1; }
done

# ---------------------------------------------------------------------------
# 4. The trust store survives an update. ca-certificates' postinst never runs
#    in a rock, so without this file update-ca-certificates rebuilds the
#    bundle from an empty list and drops every public root.
# ---------------------------------------------------------------------------
echo "==> Check: /etc/ca-certificates.conf lists the shipped roots"
run /bin/sh -c 'test -s /etc/ca-certificates.conf' \
  || { echo "ERROR: /etc/ca-certificates.conf is missing or empty" >&2; exit 1; }

echo "All supervisor smoke checks passed."
