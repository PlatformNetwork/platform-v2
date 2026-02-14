#!/bin/bash
# =============================================================================
# Nightly/Linker Config Verification
# =============================================================================
# Verifies optional nightly + fast linker flags are applied without failing
# on stable toolchains. This is a lightweight check (dry-run build).
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./test-harness.sh
source "${SCRIPT_DIR}/test-harness.sh"

platform_test_init
trap platform_cleanup_run_dir EXIT

log_info "Nightly config verification"
log_info "Defaults: nightly toolchain uses parallel rustc"
log_info "Opt-out: PLATFORM_DISABLE_NIGHTLY=1"
log_info "Override: PLATFORM_RUST_NIGHTLY=1"
log_info "Defaults: fast linker flags from config"
log_info "Opt-out: PLATFORM_DISABLE_FAST_LINKER=1"
log_info "Override: PLATFORM_FAST_LINKER_RUSTFLAGS/PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN"
log_info "Override: PLATFORM_LINKER_RUSTFLAGS/PLATFORM_LINKER_RUSTFLAGS_DARWIN"

    if [ -z "${PLATFORM_NIGHTLY_RUSTFLAGS+x}" ]; then
        export PLATFORM_NIGHTLY_RUSTFLAGS="-Z threads=0"
    fi
    export PLATFORM_NIGHTLY_RUSTFLAGS=""
    log_info "Nightly Rust disabled via opt-out"
elif [ "${PLATFORM_RUST_NIGHTLY:-0}" = "1" ] || [ "${RUSTUP_TOOLCHAIN:-}" = "nightly" ]; then
    export RUSTUP_TOOLCHAIN="nightly"
    export PLATFORM_NIGHTLY_RUSTFLAGS="${PLATFORM_NIGHTLY_RUSTFLAGS:--Z threads=0}"
    log_info "Nightly Rust enabled (parallel rustc)"
else
    log_info "Nightly Rust not requested; using default toolchain"
fi

if [ "${PLATFORM_DISABLE_FAST_LINKER:-0}" = "1" ]; then
    export PLATFORM_FAST_LINKER_RUSTFLAGS=""
    export PLATFORM_FAST_LINKER_RUSTFLAGS_DARWIN=""
    export PLATFORM_LINKER_RUSTFLAGS=""
    export PLATFORM_LINKER_RUSTFLAGS_DARWIN=""
    log_info "Fast linker disabled via opt-out"
fi

log_info "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-default}"
log_info "PLATFORM_NIGHTLY_RUSTFLAGS=${PLATFORM_NIGHTLY_RUSTFLAGS:-}"
log_info "PLATFORM_LINKER_RUSTFLAGS=${PLATFORM_LINKER_RUSTFLAGS:-}"
log_info "PLATFORM_LINKER_RUSTFLAGS_DARWIN=${PLATFORM_LINKER_RUSTFLAGS_DARWIN:-}"

log_info "Running cargo check (dry-run build)"
if cargo check --workspace 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/nightly-config-check.log"; then
    log_success "Config verification completed"
else
    log_failure "Config verification failed"
    exit 1
fi