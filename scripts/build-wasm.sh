#!/bin/bash
set -e

# Ensure wasm32 target is installed
rustup target add wasm32-unknown-unknown 2>/dev/null || true

# ---------------------------------------------------------------------------
# Build a challenge crate when a package name is supplied, otherwise build
# the chain-runtime WASM.
# ---------------------------------------------------------------------------

if [ -n "$1" ]; then
    CRATE="$1"
    echo "Building challenge crate: $CRATE ..."

    cargo build --release --target wasm32-unknown-unknown \
        -p "$CRATE" \
        --no-default-features

    # Derive the expected artefact name (hyphens become underscores)
    ARTIFACT_NAME=$(echo "$CRATE" | tr '-' '_')
    WASM_PATH="target/wasm32-unknown-unknown/release/${ARTIFACT_NAME}.wasm"

    if [ -f "$WASM_PATH" ]; then
        SIZE=$(du -h "$WASM_PATH" | cut -f1)
        echo "WASM built successfully: $WASM_PATH ($SIZE)"

        if command -v wasm-opt &> /dev/null; then
            echo "Optimizing WASM with wasm-opt..."
            wasm-opt -Oz -o "${WASM_PATH%.wasm}_optimized.wasm" "$WASM_PATH"
            OPT_SIZE=$(du -h "${WASM_PATH%.wasm}_optimized.wasm" | cut -f1)
            echo "Optimized WASM: ${WASM_PATH%.wasm}_optimized.wasm ($OPT_SIZE)"
        else
            echo "wasm-opt not found. Install with: cargo install wasm-opt"
        fi
    else
        echo "ERROR: WASM build failed — expected $WASM_PATH"
        exit 1
    fi
else
    echo "Building chain-runtime WASM..."

    cargo build --release --target wasm32-unknown-unknown \
        -p mini-chain-chain-runtime \
        --no-default-features

    WASM_PATH="target/wasm32-unknown-unknown/release/platform_chain_chain_runtime.wasm"

    if [ -f "$WASM_PATH" ]; then
        SIZE=$(du -h "$WASM_PATH" | cut -f1)
        echo "WASM built successfully: $WASM_PATH ($SIZE)"

        if command -v wasm-opt &> /dev/null; then
            echo "Optimizing WASM with wasm-opt..."
            wasm-opt -Oz -o "${WASM_PATH%.wasm}_optimized.wasm" "$WASM_PATH"
            OPT_SIZE=$(du -h "${WASM_PATH%.wasm}_optimized.wasm" | cut -f1)
            echo "Optimized WASM: ${WASM_PATH%.wasm}_optimized.wasm ($OPT_SIZE)"
        else
            echo "wasm-opt not found. Install with: cargo install wasm-opt"
        fi
    else
        echo "ERROR: WASM build failed"
        exit 1
    fi
fi
