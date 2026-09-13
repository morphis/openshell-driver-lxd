.PHONY: build release check test test-lxd-client test-driver test-conformance test-upstream-e2e setup-lxd-test-env fmt fmt-check clippy shellcheck doc static-checks proto sync-proto run clean

build:
	cargo build --workspace

release:
	cargo build --release --workspace

check:
	cargo check --workspace --all-targets

test: test-lxd-client test-driver

test-lxd-client: setup-lxd-test-env
	cargo test -p lxd-client

# Runs the driver's unit and integration tests. The integration tests
# (crates/openshell-driver-lxd/tests/driver_lxd) start the driver binary and
# boot real sandboxes on a live LXD, so they need the `lxc` CLI, `skopeo`,
# `umoci`, and `mksquashfs` (squashfs-tools) on PATH plus outbound access to
# ghcr.io: the sandbox image is imported on first use. Sandboxes run a
# stand-in supervisor built from examples/, not the real one, which needs a
# gateway. They also share one LXD daemon and default project, so run them
# single-threaded to avoid cross-test interference in lifecycle watches.
# `cargo test -p openshell-driver-lxd -- --ignored` runs the tests for known gaps.
test-driver:
	cargo test -p openshell-driver-lxd -- --test-threads=1

# Runs upstream OpenShell's conformance suite against a gateway backed by this
# driver, in the environment scripts/openshell-env.sh provides with its pinned
# OpenShell release. Needs the same tools and network access as test-driver,
# plus curl, openssl and git. Not part of `test`: it downloads the pinned
# release and takes a few minutes on a cold cache.
test-conformance:
	./scripts/conformance.sh

# Runs upstream OpenShell's end-to-end tests for sandbox policy enforcement,
# Landlock and inference routing against the same environment and pinned
# release as test-conformance. Additionally needs rootless podman (with uidmap
# and passt) and python3 >= 3.11. Takes several minutes, plus about one more
# on a cold cache to fetch and build the tests.
test-upstream-e2e:
	./scripts/upstream-e2e.sh

# Provisions LXD for lxd-client's integration tests (see
# crates/lxd-client/tests/integration.rs). Idempotent; a prerequisite of
# `test` so the same command works locally and in CI.
setup-lxd-test-env:
	sudo ./scripts/setup-lxd-test-env.sh

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

# Lints the shell scripts under scripts/.
shellcheck:
	shellcheck scripts/*.sh

# Builds the API docs, treating warnings (e.g. broken intra-doc links) as
# errors so documentation stays valid.
doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

# Runs all static checks: formatting, linting, shell linting, and docs.
static-checks: fmt-check clippy shellcheck doc

# Builds computev1 (and runs proto codegen if inputs changed).
proto:
	cargo build -p computev1

# Proto files vendored from upstream NVIDIA/OpenShell. compute_driver.proto is
# the driver contract itself; options.proto defines the custom field and method
# options it imports (e.g. the `secret` field option on sandbox_token) and must
# be resolvable on protoc's include path for codegen to succeed.
UPSTREAM_PROTOS := compute_driver.proto options.proto

# OpenShell release the vendored protos are taken from. Keep it in step with
# the release pinned in scripts/openshell-env.sh, which the test suites run
# against.
OPENSHELL_REF ?= v0.0.116

# Sync proto/ with upstream NVIDIA/OpenShell at $(OPENSHELL_REF).
sync-proto:
	@changed=""; \
	for p in $(UPSTREAM_PROTOS); do \
		curl -fsSL "https://raw.githubusercontent.com/NVIDIA/OpenShell/$(OPENSHELL_REF)/proto/$$p" \
			-o /tmp/openshell_upstream_$$p || rm -f /tmp/openshell_upstream_$$p; \
		if [ ! -s /tmp/openshell_upstream_$$p ]; then \
			echo "ERROR: failed to fetch proto/$$p from upstream $(OPENSHELL_REF)" >&2; \
			exit 1; \
		fi; \
		if ! diff -q /tmp/openshell_upstream_$$p proto/$$p > /dev/null 2>&1; then \
			cp /tmp/openshell_upstream_$$p proto/$$p; \
			changed="$$changed proto/$$p"; \
		fi; \
	done; \
	if [ -z "$$changed" ]; then \
		echo "protos are already in sync with upstream $(OPENSHELL_REF)"; \
	else \
		echo "==> updated:$$changed"; \
		cargo build --workspace && \
		if [ -t 0 ]; then \
			read -r -p "Would you like to commit changes to$$changed (Y/n)? " answer; \
			if [ "$${answer:-y}" = "y" ] || [ "$${answer:-y}" = "Y" ]; then \
				git commit -S -s -m "chore(proto): sync protos with upstream $(OPENSHELL_REF)" --$$changed; \
			fi; \
		else \
			echo "==>$$changed updated; please commit the change" >&2; \
			exit 1; \
		fi; \
	fi

run:
	cargo run -p openshell-driver-lxd -- $(ARGS)

clean:
	cargo clean
