<div align="center">

# ρlατfοrm

**Distributed validator network for decentralized AI evaluation on Bittensor**

[![CI](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml/badge.svg)](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml)
[![Coverage](https://platformnetwork.github.io/platform/badges/coverage.svg)](https://github.com/PlatformNetwork/platform/actions)
[![License](https://img.shields.io/github/license/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/stargazers)
[![Rust](https://img.shields.io/badge/rust-1.90+-orange.svg)](https://www.rust-lang.org/)

![Platform Banner](assets/banner.jpg)

![Alt](https://repobeats.axiom.co/api/embed/4b44b7f7c97e0591af537309baea88689aefe810.svg "Repobeats analytics image")

</div>

---

## Introduction

Platform is a **WASM-first, peer-to-peer validator network** that evaluates miner submissions for Bittensor challenges. Validators run deterministic WASM runtimes in production, reach consensus over libp2p, and submit stake-weighted results to the chain. Docker is reserved for local and CI test harnesses only.

**Key properties**
- Fully decentralized P2P network (libp2p gossipsub + DHT)
- Stake-weighted PBFT-style consensus for challenge state
- WASM-first challenge execution with strict resource limits
- Deterministic scoring and transparent weight submission

**Documentation index**
- [Architecture](docs/architecture.md)
- [Validator Operations](docs/operations/validator.md)
- [Security Model](docs/security.md)
- [Challenges](docs/challenges.md)
- [Challenge Integration Guide](docs/challenge-integration.md)

---

## Network Overview

```mermaid
flowchart LR
    S[Sudo Owner] -->|Signed challenge actions| P2P[(libp2p Mesh)]
    P2P --> DHT[(DHT: submissions + consensus state)]
    P2P --> V1[Validator 1]
    P2P --> V2[Validator 2]
    P2P --> VN[Validator N]
    V1 -->|Evaluations + votes| P2P
    V2 -->|Evaluations + votes| P2P
    VN -->|Evaluations + votes| P2P
    V1 -->|Weights| BT[Bittensor Chain]
    V2 -->|Weights| BT
    VN -->|Weights| BT
```

---

## Quick Start (Validator)

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cp .env.example .env
# Edit .env: add your VALIDATOR_SECRET_KEY (BIP39 mnemonic)
mkdir -p data
cargo build --release --bin validator-node
./target/release/validator-node --data-dir ./data --secret-key "${VALIDATOR_SECRET_KEY}"
```

See [Validator Operations](docs/operations/validator.md) for full requirements, configuration, and monitoring.

---

## Architecture

Platform coordinates validators over libp2p and anchors finalized weights to Bittensor. Detailed flows are documented in [docs/architecture.md](docs/architecture.md), including consensus and data storage.

---

## Operations

- **Production**: WASM runtime only, no Docker dependency.
- **Testing**: Docker is used exclusively for integration harnesses (`./scripts/test-comprehensive.sh`).

See [docs/operations/validator.md](docs/operations/validator.md) for deployment guidance.

---

## Security

Platform enforces stake-weighted admission, signed P2P messages, and a hardened runtime policy for challenges. See [docs/security.md](docs/security.md) for the full security model and runtime isolation diagram.

---

## Challenges

Challenges are WASM modules that define evaluation logic. The lifecycle, registration flow, and runtime constraints are covered in [docs/challenges.md](docs/challenges.md).

---

## License

MIT
