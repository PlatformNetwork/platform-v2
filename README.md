<div align="center">

# ρlατfοrm

**Distributed validator network for decentralized AI evaluation on Bittensor**

[![CI](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml/badge.svg)](https://github.com/PlatformNetwork/platform/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/PlatformNetwork/platform)](https://github.com/PlatformNetwork/platform/stargazers)
[![Rust](https://img.shields.io/badge/rust-1.90+-orange.svg)](https://www.rust-lang.org/)

![Platform Banner](assets/banner.jpg)

![Alt](https://repobeats.axiom.co/api/embed/4b44b7f7c97e0591af537309baea88689aefe810.svg "Repobeats analytics image")

</div>

---

## Introduction

**Platform** is a decentralized evaluation framework that enables trustless assessment of AI agents through configurable challenges on the Bittensor network. By connecting multiple validators through a Byzantine fault-tolerant consensus mechanism, Platform ensures honest and reproducible evaluation of agent submissions while preventing gaming and manipulation.

> **Want to run a validator?** See the [Validator Guide](docs/validator.md) for setup instructions.

### Key Features

- **Decentralized Evaluation**: Multiple validators independently evaluate agent submissions
- **Challenge-Based Architecture**: Modular Docker containers define custom evaluation logic
- **Byzantine Fault Tolerance**: PBFT consensus with $2f+1$ threshold ensures correctness
- **Commit-Reveal Weights**: Cryptographic scheme prevents weight copying attacks
- **Merkle State Sync**: Verifiable distributed database with optimistic execution
- **Multi-Mechanism Support**: Each challenge maps to a Bittensor mechanism for independent weight setting
- **Stake-Weighted Security**: Minimum 1000 TAO stake required for validator participation

---

## System Overview

Platform involves three main participants:

- **Miners**: Submit AI agents (code/models) to challenges for evaluation
- **Validators**: Run challenge containers, evaluate agents, and submit weights to Bittensor
- **Sudo Owner**: Configures challenges via signed `SudoAction` messages

The coordination between validators ensures that only verified, consensus-validated results influence the weight distribution on Bittensor.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SUDO OWNER                                      │
│                    (Creates, Updates, Removes Challenges)                    │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SHARED BLOCKCHAIN STATE                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Challenge A │  │ Challenge B │  │ Challenge C │  │     ...     │        │
│  │ (Docker)    │  │ (Docker)    │  │ (Docker)    │  │             │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     Distributed Database (Merkle Trie)                │  │
│  │              Evaluation Results • Scores • Agent Data                 │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
            ▼                     ▼                     ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│   VALIDATOR 1     │ │   VALIDATOR 2     │ │   VALIDATOR N     │
├───────────────────┤ ├───────────────────┤ ├───────────────────┤
│ ┌───────────────┐ │ │ ┌───────────────┐ │ │ ┌───────────────┐ │
│ │ Challenge A   │ │ │ │ Challenge A   │ │ │ │ Challenge A   │ │
│ │ Challenge B   │ │ │ │ Challenge B   │ │ │ │ Challenge B   │ │
│ │ Challenge C   │ │ │ │ Challenge C   │ │ │ │ Challenge C   │ │
│ └───────────────┘ │ │ └───────────────┘ │ │ └───────────────┘ │
│                   │ │                   │ │                   │
│ Evaluates agents  │ │ Evaluates agents  │ │ Evaluates agents  │
│ Shares results    │ │ Shares results    │ │ Shares results    │
└─────────┬─────────┘ └─────────┬─────────┘ └─────────┬─────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   BITTENSOR CHAIN     │
                    │   (Weight Submission) │
                    │  Each Epoch (~72min)  │
                    └───────────────────────┘
```

---

## Miners (Agent Submitters)

### Operations

1. **Agent Development**:
   - Miners develop AI agents that solve challenge-specific tasks
   - Agents are packaged as code submissions with metadata

2. **Submission**:
   - Submit agent to any validator via HTTP API
   - Agent is stored in distributed database and synced across all validators
   - Submission includes: source code, miner hotkey, metadata

3. **Evaluation**:
   - All validators independently evaluate the agent
   - Evaluation runs in isolated Docker containers
   - Results are stored in Merkle-verified distributed database

4. **Weight Distribution**:
   - At epoch end, validators aggregate scores
   - Weights are submitted to Bittensor proportional to agent performance

### Formal Definitions

- **Agent Submission**: $A_i = (code, hotkey_i, metadata)$
- **Submission Hash**: $h_i = \text{SHA256}(A_i)$
- **Evaluation Score**: $s_i^v \in [0, 1]$ - score from validator $v$ for agent $i$

---

## Validators

### Operations

1. **Challenge Synchronization**:
   - Pull challenge Docker images configured by Sudo owner
   - All validators run identical challenge containers
   - Health monitoring ensures container availability

2. **Agent Evaluation**:
   - Receive agent submissions via P2P gossipsub
   - Execute evaluation in sandboxed Docker environment
   - Compute score $s \in [0, 1]$ based on challenge criteria

3. **Result Sharing**:
   - Broadcast `EvaluationResult` to all peers via P2P
   - Store results in distributed Merkle-verified database
   - Verify state root matches across validators

4. **Score Aggregation**:
   - Collect evaluations from all validators for each agent
   - Compute stake-weighted median to resist manipulation
   - Detect and exclude outlier validators

5. **Weight Calculation**:
   - Convert aggregated scores to normalized weights
   - Apply softmax or linear normalization
   - Cap maximum weight per agent to prevent dominance

6. **Weight Submission**:
   - Commit weight hash during commit window
   - Reveal weights during reveal window
   - Submit to Bittensor per-mechanism

### Formal Definitions

- **Evaluation**: $E_i^v = (h_i, s_i^v, t, \sigma_v)$ where $\sigma_v$ is validator signature
- **Aggregated Score** (stake-weighted median):

$$\bar{s}_i = \text{median}(\{s_i^v : v \in \mathcal{V}\}) \text{ weighted by stake}$$

- **Confidence Score**:

$$c_i = \exp\left( -\frac{\sigma_i}{\tau} \right)$$

Where $\sigma_i$ is standard deviation of scores and $\tau$ is sensitivity scale.

---

## Incentive Mechanism

### Weight Calculation

Platform supports two normalization methods:

#### 1. Softmax Normalization (Default)

Converts scores to probability distribution using temperature-scaled softmax:

$$w_i = \frac{\exp(s_i / T)}{\sum_{j \in \mathcal{M}} \exp(s_j / T)}$$

Where:
- $w_i$ - normalized weight for agent $i$
- $s_i$ - aggregated score for agent $i$
- $T$ - temperature parameter (higher = more distributed)
- $\mathcal{M}$ - set of all evaluated agents

#### 2. Linear Normalization

Simple proportional distribution:

$$w_i = \frac{s_i}{\sum_{j \in \mathcal{M}} s_j}$$

### Weight Capping

To prevent single-agent dominance, weights are capped:

$$w_i' = \min(w_i, w_{max})$$

Excess weight is redistributed to uncapped agents:

$$\text{excess} = \sum_{i: w_i > w_{max}} (w_i - w_{max})$$

$$w_j' = w_j + \frac{\text{excess}}{|\{k : w_k < w_{max}\}|} \quad \forall j : w_j < w_{max}$$

Default $w_{max} = 0.5$ (50% maximum per agent).

### Final Weight Conversion

Weights are converted to Bittensor u16 format:

$$W_i = \lfloor w_i' \times 65535 \rfloor$$

---

## Commit-Reveal Protocol

To prevent weight copying attacks, Platform uses a commit-reveal scheme compatible with Subtensor:

### Commit Phase

1. Generate random salt: `salt ← random 128 bits`

2. Compute commit hash using SCALE encoding + Blake2b-256:

```
H = Blake2b_256(SCALE(account, netuid_index, uids, weights, salt, version_key))
```

Where:
```
netuid_index = netuid × 256 + mechanism_id
```

3. Submit commit: `commit_mechanism_weights(netuid, mechanism_id, H)`

### Reveal Phase

After commit window closes:

1. Submit reveal: `reveal_mechanism_weights(netuid, mechanism_id, uids, weights, salt, version_key)`

2. Subtensor verifies: `H == Blake2b_256(SCALE(...))`

### Security Properties

- **Hiding**: Hash reveals nothing about weights before reveal
- **Binding**: Cannot change weights after commit
- **Fairness**: All validators must commit before any reveal

---

## Consensus Mechanism

### PBFT (Practical Byzantine Fault Tolerance)

Platform uses simplified PBFT for validator consensus:

#### Threshold

For $n$ validators with maximum $f$ faulty nodes:

$$\text{threshold} = 2f + 1 = \left\lfloor \frac{2n}{3} \right\rfloor + 1$$

#### Consensus Flow

1. **Propose**: Leader broadcasts `Proposal(action, block_height)`
2. **Vote**: Validators verify and broadcast `Vote(proposal_id, approve/reject)`
3. **Commit**: If $\geq \text{threshold}$ approvals received, apply action

#### Supported Actions

- `SudoAction::AddChallenge` - Add new challenge container
- `SudoAction::UpdateChallenge` - Update challenge configuration
- `SudoAction::RemoveChallenge` - Remove challenge
- `SudoAction::SetRequiredVersion` - Mandatory version update
- `NewBlock` - State checkpoint

### Distributed Database Consensus

State synchronization uses Merkle trie verification:

```
StateRoot = MerkleRoot({(k_i, v_i) : ∀ entries})
```

Validators periodically compare state roots:

- **In Consensus**: $\geq 2/3$ validators share same root
- **Diverged**: Minority validators must sync from majority

---

## Score Aggregation

### Stake-Weighted Aggregation

Each validator's score is weighted by their stake:

$$\bar{s}_i = \frac{\sum_{v \in \mathcal{V}} S_v \cdot s_i^v}{\sum_{v \in \mathcal{V}} S_v}$$

Where $S_v$ is the stake of validator $v$.

### Outlier Detection

Validators with anomalous scores are detected using z-score:

$$z_v = \frac{s_i^v - \mu_i}{\sigma_i}$$

Where $\mu_i$ and $\sigma_i$ are mean and standard deviation of scores for agent $i$.

Validators with $|z_v| > z_{threshold}$ (default 2.0) are excluded from aggregation.

### Confidence Calculation

Agreement among validators determines confidence:

$$\text{confidence}_i = \exp\left( -\frac{\sigma_i}{0.1} \right)$$

Low confidence (high variance) may exclude agent from weights.

---

## Security Considerations

### Stake-Based Security

- **Minimum Stake**: 1000 TAO required for validator participation
- **Sybil Resistance**: Creating fake validators requires significant capital
- **Stake Validation**: All P2P messages verified against metagraph stakes

### Network Protection

| Protection | Configuration |
|------------|---------------|
| Rate Limiting | 100 msg/sec per peer |
| Connection Limiting | 5 connections per IP |
| Blacklist Duration | 1 hour for violations |
| Failed Attempt Limit | 10 before blacklist |

### Evaluation Isolation

- **Docker Sandboxing**: Agents run in isolated containers
- **Resource Limits**: Memory, CPU, and time constraints
- **Deterministic Execution**: All validators run identical containers

### Data Integrity

- **Merkle Verification**: All data changes update state root
- **Signature Verification**: All messages signed by validator keys
- **Optimistic Execution**: Immediate local apply, confirmed at block

---

## Formal Analysis

### Validator Utility Maximization

Validators maximize reputation by submitting accurate evaluations:

$$\max_{s_i^v} \quad \mathbb{E}[\text{reputation}_v]$$

Subject to:
- Evaluation must be reproducible: $s_i^v = \text{eval}(A_i)$
- Must match consensus: $|s_i^v - \bar{s}_i| < \epsilon$

### Miner Utility Maximization

Miners maximize reward by submitting high-performing agents:

$$\max_{A_i} \quad w_i = \frac{\exp(\bar{s}_i / T)}{\sum_j \exp(\bar{s}_j / T)}$$

Subject to:
- Agent must pass validation
- Score determined by challenge criteria

### Security Guarantees

1. **Byzantine Tolerance**: System remains correct with up to $f = \lfloor(n-1)/3\rfloor$ faulty validators

2. **Weight Integrity**: Commit-reveal prevents:
   - Weight copying before deadline
   - Post-hoc weight modification

3. **Evaluation Fairness**: 
   - Deterministic Docker execution
   - Outlier detection excludes manipulators
   - Stake weighting resists Sybil attacks

4. **Liveness**: System progresses if $> 2/3$ validators are honest and connected

---

## Epoch Lifecycle

Each Bittensor epoch (~360 blocks, ~72 minutes):

### Continuous Evaluation

**Evaluation runs continuously** throughout the entire epoch. Validators constantly:
- Receive and process agent submissions
- Execute evaluations in Docker containers
- Sync results via P2P to distributed database
- Aggregate scores from all validators

### Weight Submission (At Epoch Boundary)

At the end of each epoch, weights are submitted to Bittensor:

| Event | Timing | Activity |
|-------|--------|----------|
| Commit Window Opens | Epoch end | Validators commit weight hashes |
| Reveal Window Opens | After commit closes | Validators reveal actual weights |

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTINUOUS EVALUATION                     │
│        (Agents evaluated, results synced throughout)         │
└─────────────────────────────────┬───────────────────────────┘
                                  │ Epoch End
                                  ▼
                    ┌─────────────────────────┐
                    │   COMMIT (weight hash)  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │   REVEAL (weights)      │
                    └────────────┬────────────┘
                                 │
                                 ▼
                         Next Epoch Starts
```

---

## Quick Start

```bash
git clone https://github.com/PlatformNetwork/platform.git
cd platform
cp .env.example .env
# Edit .env: add your VALIDATOR_SECRET_KEY (BIP39 mnemonic)
docker compose up -d
```

The validator will auto-connect to `bootnode.platform.network` and sync.

## Network Requirements

**Port 9000/tcp must be open** for P2P communication.

| Port | Protocol | Usage |
|------|----------|-------|
| 9000/tcp | P2P (libp2p) | Validator communication (required) |
| 8545/tcp | HTTP | JSON-RPC API (optional) |

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `VALIDATOR_SECRET_KEY` | BIP39 mnemonic or hex key | Required |
| `SUBTENSOR_ENDPOINT` | Bittensor RPC endpoint | `wss://entrypoint-finney.opentensor.ai:443` |
| `NETUID` | Subnet UID | `100` |
| `RUST_LOG` | Log level | `info` |

---

## Auto-Update (Critical)

**All validators MUST use auto-update.** Watchtower checks for new images at synchronized times (`:00`, `:05`, `:10`, `:15`...) so all validators update together.

If validators run different versions:
- Consensus fails (state hash mismatch)
- Weight submissions rejected
- Network forks

**Do not disable Watchtower.**

---

## Conclusion

Platform creates a trustless, decentralized framework for evaluating AI agents on Bittensor. By combining:

- **PBFT Consensus** for Byzantine fault tolerance
- **Commit-Reveal** for weight submission integrity  
- **Stake-Weighted Aggregation** for Sybil resistance
- **Docker Isolation** for deterministic evaluation
- **Merkle State Sync** for verifiable distributed storage

The system ensures that only genuine, high-performing agents receive rewards, while making manipulation economically infeasible. Validators are incentivized to provide accurate evaluations through reputation mechanics, and miners are incentivized to submit quality agents through the weight distribution mechanism.

---

## License

MIT
