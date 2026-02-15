# Architecture

Platform is a **WASM-first, P2P validator network** designed for deterministic challenge evaluation on Bittensor. Validators exchange submissions, evaluation results, and consensus votes directly over libp2p, then submit finalized weights to the chain.

## Core Components

- **Validator Node (`validator-node`)**: runs P2P, consensus, and evaluation pipelines.
- **Challenge Registry**: signed metadata for active challenges (WASM modules + policies).
- **WASM Runtime Interface**: strict sandbox with resource caps and audited host functions.
- **P2P Consensus Engine**: PBFT-style voting with stake-weighted validator set.
- **Distributed Storage (DHT)**: shared submission and consensus state.

## Network Topology (P2P)

```mermaid
flowchart LR
    S[Sudo Owner] -->|Signed challenge updates| P2P[(libp2p Mesh)]
    P2P --> DHT[(DHT)]
    P2P --> V1[Validator 1]
    P2P --> V2[Validator 2]
    P2P --> VN[Validator N]
    V1 -->|Evaluations + votes| P2P
    V2 -->|Evaluations + votes| P2P
    VN -->|Evaluations + votes| P2P
    V1 -->|Final weights| BT[Bittensor Chain]
    V2 -->|Final weights| BT
    VN -->|Final weights| BT
```

## Consensus Flow (PBFT-style)

```mermaid
sequenceDiagram
    participant L as Leader
    participant V1 as Validator 1
    participant V2 as Validator 2
    participant Vn as Validator N

    L->>V1: Proposal(action, height)
    L->>V2: Proposal(action, height)
    L->>Vn: Proposal(action, height)
    V1-->>L: Vote(approve/reject)
    V2-->>L: Vote(approve/reject)
    Vn-->>L: Vote(approve/reject)
    L-->>V1: Commit(>=2f+1 approvals)
    L-->>V2: Commit(>=2f+1 approvals)
    L-->>Vn: Commit(>=2f+1 approvals)
```

## Data Flow

```mermaid
flowchart TD
    Miner[Miners] -->|Submit code + metadata| P2P[(libp2p gossipsub)]
    P2P -->|Distribute submissions| Validators[Validator Nodes]
    Validators -->|Execute WASM challenge runtime| Runtime[WASM Sandbox]
    Runtime -->|Scores + artifacts| Validators
    Validators -->|Aggregate scores + consensus| DHT[(DHT + consensus state)]
    Validators -->|Stake-weighted weights| Bittensor[Bittensor Chain]
```

## Storage Model

- **DHT entries**: submissions, evaluation results, consensus checkpoints.
- **Local persistence**: validator state and audit logs under `data/`.

## Operational Boundaries

- **WASM-first**: challenge execution uses WASM runtime in production.
- **Docker test-only**: Docker-backed harnesses are reserved for local/CI testing.
- **Consensus-driven changes**: challenge lifecycle events require PBFT approval.

## Related Documentation

- [Validator Operations](operations/validator.md)
- [Security Model](security.md)
- [Challenge Lifecycle](challenges.md)
