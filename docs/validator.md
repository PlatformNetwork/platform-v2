# Validator Guide

This guide explains how to run a Platform validator node on the Bittensor network. Validators execute challenges in the WASM runtime.

## Key Features

- **No GPU required**: validators run on CPU servers.
- **No third-party APIs**: no external model keys needed.
- **WASM-only runtime**: deterministic challenge execution.
- **P2P-only consensus**: libp2p mesh for all validator traffic.

## Validator Lifecycle

```mermaid
flowchart LR
    Start[Start validator] --> Sync[Sync metagraph + checkpoints]
    Sync --> Evaluate[Run WASM challenges]
    Evaluate --> Commit[Commit weights]
    Commit --> Reveal[Reveal weights]
    Reveal --> Submit[Submit weights to Bittensor]
    Submit --> Observe[Monitor + audit]
```

## P2P Architecture

Platform validators run as a fully peer-to-peer network with no centralized fallback services. All validator-to-validator traffic happens over libp2p on port 9000, and consensus data is exchanged directly between peers.

- **Peer discovery**: validators connect to the libp2p mesh and maintain a live peer set.
- **State sync**: checkpoints, block proposals, and commits are shared only through the P2P network.
- **No central coordinator**: there are no HTTP relays or centralized aggregators for consensus.
- **Bittensor anchoring**: the metagraph provides stake and identity, but consensus payloads flow through P2P.

## Weight-Based Consensus Flow

Consensus is driven by validator weights derived from challenge evaluations. The validator set is stake-weighted, meaning higher-stake hotkeys carry more voting power when aggregating challenge results.

1. **Stake-weighted validator set**: each validator’s voting power is proportional to its Bittensor stake in the metagraph.
2. **Challenge evaluation**: validators execute active challenges, producing raw scores.
3. **Commit-reveal weights**: validators commit weight vectors, then reveal them.
4. **Epoch aggregation**: stake-weighted aggregation produces canonical weights.
5. **Consensus agreement**: validators agree on the aggregated weights and state hash.
6. **Weight submission**: finalized weights are submitted back to Bittensor.

```mermaid
sequenceDiagram
    participant V as Validator
    participant P2P as libp2p Mesh
    participant BT as Bittensor

    V->>P2P: Commit(weight hash)
    V->>P2P: Reveal(weights)
    P2P-->>V: Aggregated weights + state hash
    V->>BT: Submit weights
```

## Quick Start

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform

# Configure environment
cp .env.example .env
nano .env  # Set VALIDATOR_SECRET_KEY to your BIP39 mnemonic

# Start the validator
docker compose up -d

# View logs
docker compose logs -f validator

# Check status
docker compose ps
```

### Building from Source (Alternative)

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cargo build --release --bin validator-node

# Run with environment variable
export VALIDATOR_SECRET_KEY="your 24 word mnemonic here"
./target/release/validator-node
```

## Requirements

### Hardware

| Resource | Minimum | Recommended |
| --- | --- | --- |
| CPU | 4 vCPU | 8 vCPU |
| RAM | 16 GB | 32 GB |
| Storage | 250 GB SSD | 500 GB NVMe |
| Network | 100 Mbps | 100 Mbps |

### Network

**Port 9000/tcp must be open** for P2P communication.

### Software

- Linux (Ubuntu 22.04+ recommended)

### Bittensor

- **Minimum stake**: 1000 TAO.
- Registered hotkey on subnet.
- BIP39 mnemonic or hex private key.

## Configuration Reference

### Environment Variables (.env file)

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `VALIDATOR_SECRET_KEY` | BIP39 mnemonic (24 words) | - | **Yes** |
| `SUBTENSOR_ENDPOINT` | Bittensor RPC endpoint | `wss://entrypoint-finney.opentensor.ai:443` | No |
| `NETUID` | Subnet UID | `100` | No |
| `RPC_PORT` | JSON-RPC API port | `8080` | No |
| `P2P_PORT` | libp2p P2P port | `8090` | No |
| `BOOTNODE_PORT` | Bootnode P2P port | `8090` | No |
| `WITH_BOOTNODE` | Run integrated bootnode | `false` | No |
| `RUST_LOG` | Log level (`debug`, `info`, `warn`, `error`) | `info` | No |
| `BOOTSTRAP_PEERS` | Bootstrap peer multiaddrs (comma-separated) | Auto-discovered | No |

### Example .env file

```bash
# Required: Your validator hotkey mnemonic
VALIDATOR_SECRET_KEY=word1 word2 word3 ... word24

# Optional: Override defaults
NETUID=100
RPC_PORT=8080
P2P_PORT=8090
RUST_LOG=info,validator_node=debug
```

### Network Ports

| Port | Protocol | Usage | Required |
| --- | --- | --- | --- |
| 8090/tcp | libp2p | P2P validator communication | Yes |
| 8080/tcp | HTTP | JSON-RPC API | No |

## Monitoring

### Check Validator Status

```bash
# View logs (Docker Compose)
docker compose logs -f validator

# Check container status
docker compose ps

# View resource usage
docker stats platform-validator
```

### JSON-RPC Health Check

```bash
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_health","id":1}'
```

Expected response:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "peers": 5,
    "isSyncing": false,
    "shouldHaveWeights": true
  },
  "id": 1
}
```

### List Available RPC Methods

```bash
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"rpc_methods","id":1}'
```

## References

- [Validator Operations](operations/validator.md)
- [Architecture](architecture.md)
- [Security Model](security.md)
