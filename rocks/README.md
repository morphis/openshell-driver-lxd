# rocks/

Three rocks, built from **one pinned upstream revision**, currently
`a8f98ec09de502bad1edc5b1a903382d27b8be0e` (OpenShell v0.1.0-pre.11):

| rock | definition | base | what it is |
|---|---|---|---|
| `openshell-gateway` | `../rockcraft.yaml` | `ubuntu@26.04` | the OpenShell gateway and this driver, under Pebble |
| `openshell-supervisor` | `supervisor/rockcraft.yaml` | `ubuntu@26.04` | the out-of-workload half of a sandbox — a rootfs the driver boots the companion container from |
| `openshell-sandbox` | `sandbox/rockcraft.yaml` | `bare` | the in-workload half — a static binary the driver mounts into the workload container |

They pin the same revision on purpose. From OpenShell v0.1.0 a sandbox is a
gateway, a supervisor companion and a workload boundary speaking one protocol
to each other; three of them from different revisions is a sandbox that does
not attach, and the version strings the images report are not a reliable
signal of which revision they came from. Bump the `source-commit` in all three
together, and the digests pinned in `crates/openshell-driver-lxd/src/config.rs`
with them.

`sandbox/` is `bare` because the driver never runs that image: it extracts
`/openshell-sandbox` into a digest-keyed LXD storage volume and mounts it into
a workload container whose rootfs is the user's own image. The binary is
statically linked against musl for the same reason — the libc of the image it
lands in is unknown. `supervisor/` *is* run, so it is a real rootfs: the driver
replaces its init with its own shell script, which needs `/bin/sh`, `ip` and
curl, none of which upstream's distroless image has.

## Building locally

```
rockcraft pack                      # gateway, from the repository root
rockcraft pack -v                   # ...with build output
cd rocks/supervisor && rockcraft pack
cd rocks/sandbox && rockcraft pack
```

`make rock` packs the gateway rock; `make test-rock` runs the smoke tests in
`../tests/rock/`. CI (`.github/workflows/rock.yaml`) packs and smoke-tests all
three on every push and pull request, and publishes multi-arch manifests to
GHCR on push to `main`.

## Why not upstream's published images

`openshell-supervisor` and `openshell-sandbox` are published upstream too, and
the driver defaults to them, pinned by digest. These rocks exist because the
supervisor image upstream publishes is distroless — the driver has to inject a
static busybox to run its init script in it — and because building all three
from one revision here is what makes a mismatch impossible rather than merely
unlikely.
