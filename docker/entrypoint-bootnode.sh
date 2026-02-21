#!/bin/bash
set -euo pipefail

echo "=== Platform Bootnode ==="
echo "P2P Port: ${P2P_PORT:-8090}"
echo ""

# Bootnode secret key is required for a stable PeerId
if [ -z "${BOOTNODE_SECRET_KEY:-}" ]; then
    echo "ERROR: BOOTNODE_SECRET_KEY is required (stable PeerId depends on it)"
    exit 1
fi

ARGS="--data-dir ${DATA_DIR:-/data}"
ARGS="$ARGS --listen-addr /ip4/0.0.0.0/tcp/${P2P_PORT:-8090}"
ARGS="$ARGS --secret-key ${BOOTNODE_SECRET_KEY}"
ARGS="$ARGS --netuid ${NETUID:-100}"

if [ -n "${SUBTENSOR_ENDPOINT:-}" ]; then
    ARGS="$ARGS --subtensor-endpoint ${SUBTENSOR_ENDPOINT}"
fi

# Bootnode can optionally connect to other bootnodes
if [ -n "${BOOTSTRAP_PEERS:-}" ]; then
    IFS=',' read -ra PEERS <<< "${BOOTSTRAP_PEERS}"
    for peer in "${PEERS[@]}"; do
        ARGS="$ARGS --bootstrap ${peer}"
    done
fi

echo "Starting bootnode..."
exec validator-node ${ARGS}
