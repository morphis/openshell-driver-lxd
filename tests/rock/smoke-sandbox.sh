#!/usr/bin/env bash
# Smoke test for the openshell-sandbox rock.
# Invoked by the CI build job after rockcraft-pack.
# Proves: the image ships exactly the boundary binary the driver extracts,
# at the path the driver looks for, as a regular (non-symlink) statically
# linked executable. The rock is `base: bare`, so there is no shell inside
# the image and every check runs from the host.
set -euo pipefail

ROCK_DIR="${ROCK_DIR:-rocks/sandbox}"
IMAGE="openshell-sandbox:test"
BINARY="openshell-sandbox"

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

# The image has no shell and no entrypoint to run, so create a stopped
# container and inspect its filesystem from the host.
CONTAINER=$(docker create "${IMAGE}")
trap 'docker rm -f "${CONTAINER}" > /dev/null 2>&1' EXIT

# ---------------------------------------------------------------------------
# 1. /openshell-sandbox exists at the image root, as a regular file.
#    The driver rejects a symlink there, so check the tar entry type.
# ---------------------------------------------------------------------------
echo "==> Check: ${BINARY} present at image root as a regular file"
ENTRY_TYPE=$(docker export "${CONTAINER}" | tar -tvf - | awk -v binary="${BINARY}" '
  {
    path = $NF
    sub("^\\./", "", path)
    sub("^/", "", path)
    if (path == binary) {
      res = substr($1, 1, 1)
    }
  }
  END {
    if (res) print res
  }')
if [[ -z "${ENTRY_TYPE}" ]]; then
  echo "ERROR: /${BINARY} not found in the image" >&2
  exit 1
fi
[[ "${ENTRY_TYPE}" == "-" ]] \
  || { echo "ERROR: /${BINARY} is not a regular file (tar type '${ENTRY_TYPE}'); the driver rejects anything but a regular file there" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2. The binary is executable.
# ---------------------------------------------------------------------------
echo "==> Check: ${BINARY} is executable"
WORK_DIR=$(mktemp -d)
trap 'docker rm -f "${CONTAINER}" > /dev/null 2>&1; rm -rf "${WORK_DIR}"' EXIT
docker cp "${CONTAINER}:/${BINARY}" "${WORK_DIR}/${BINARY}"
test -x "${WORK_DIR}/${BINARY}"

# ---------------------------------------------------------------------------
# 3. The binary is statically linked.
#    Rust's musl target produces a static-PIE, which `file` reports as
#    "static-pie linked" rather than "statically linked"; both are static,
#    and what actually matters is that it is not dynamic.
# ---------------------------------------------------------------------------
echo "==> Check: ${BINARY} is statically linked"
DESCRIPTION=$(file "${WORK_DIR}/${BINARY}")
case "${DESCRIPTION}" in
  *"dynamically linked"*|*"interpreter"*)
    echo "ERROR: /${BINARY} is not statically linked:" >&2
    echo "${DESCRIPTION}" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# 4. The image ships nothing else at its root beyond the binary and the
#    baseline OCI scaffolding — the rock is bare, everything else is dead
#    weight that would end up digest-keyed into every sandbox volume.
# ---------------------------------------------------------------------------
echo "==> Check: image rootfs contains nothing beyond the binary and baseline entries"
EXTRA=$(docker export "${CONTAINER}" | tar -tf - | sed -e 's/^\.\///' -e 's/\/.*$//' | sort -u | grep -v -E "^(${BINARY}|\.dockerenv|\.rock|dev|etc|proc|root|sys|tmp|usr|var)$" || true)
if [[ -n "${EXTRA}" ]]; then
  echo "ERROR: unexpected entries in the image root:" >&2
  echo "${EXTRA}" >&2
  exit 1
fi

echo "All sandbox smoke checks passed."
