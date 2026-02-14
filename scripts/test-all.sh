#!/bin/bash
# =============================================================================
# Platform Standard Test Suite
# =============================================================================
# Entry point for local/unit test runs. Docker is not required.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./test-harness.sh
source "${SCRIPT_DIR}/test-harness.sh"

PASSED=0
FAILED=0
SKIPPED=0

platform_test_init
trap platform_cleanup_run_dir EXIT
log_info "Opt-in: PLATFORM_RUST_NIGHTLY=1 (nightly parallel rustc)"
log_info "Opt-in: PLATFORM_FAST_LINKER=mold|lld"

if [ "${PLATFORM_RUST_NIGHTLY:-0}" = "1" ]; then
    export RUSTUP_TOOLCHAIN="nightly"
    export PLATFORM_NIGHTLY_RUSTFLAGS="${PLATFORM_NIGHTLY_RUSTFLAGS:--Z threads=0}"
    log_info "Nightly Rust enabled (parallel rustc)"
fi

if [ -n "${PLATFORM_FAST_LINKER:-}" ]; then
    case "${PLATFORM_FAST_LINKER}" in
        mold|lld)
            export PLATFORM_LINKER_RUSTFLAGS="${PLATFORM_LINKER_RUSTFLAGS:--C link-arg=-fuse-ld=${PLATFORM_FAST_LINKER}}"
            log_info "Fast linker enabled: ${PLATFORM_FAST_LINKER}"
            ;;
        *)
            log_warning "Unsupported PLATFORM_FAST_LINKER=${PLATFORM_FAST_LINKER} (expected mold or lld)"
            ;;
    esac
fi
log_info "=== Platform Test Suite ==="
log_info "Artifacts: ${PLATFORM_TEST_ARTIFACTS_DIR}"
log_info "Run dir: ${PLATFORM_TEST_RUN_DIR}"

log_info "[1/2] Building workspace"
if cargo build --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/build.log"; then
    log_success "Build completed"
else
    log_failure "Build failed"
    exit 1
fi

log_info "[2/2] Running unit tests"
if cargo test --workspace --release 2>&1 | tee "${PLATFORM_TEST_LOG_DIR}/unit-tests.log"; then
    log_success "Unit tests completed"
else
    log_failure "Unit tests failed"
fi

log_info "Test summary"
log_info "Passed: ${PASSED}"
log_info "Failed: ${FAILED}"
log_info "Skipped: ${SKIPPED}"

if [ "${FAILED}" -ne 0 ]; then
    exit 1
fi