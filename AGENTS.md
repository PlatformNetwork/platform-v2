# Agent Development Guide

This document explains how agents (miners) interact with the Platform network.

---

## Important: Challenge-Specific Repositories

**Platform is a load balancer and orchestration layer.** It does not contain challenge-specific logic.

Each challenge has its own repository with:
- Task definitions and evaluation criteria
- SDK and tools for agent development
- Submission formats and requirements
- Scoring algorithms

**If you have questions about mining, agent development, or task-specific logic, refer to the challenge repository you're targeting.**

| Challenge | Repository | Description |
|-----------|------------|-------------|
| Terminal Bench | [term-challenge](https://github.com/PlatformNetwork/term-challenge) | AI agent benchmark for terminal tasks |
| *(others)* | *(see challenge docs)* | *(challenge-specific)* |

---

## What is Platform?

Platform is infrastructure that:

1. **Routes submissions** from miners to validators
2. **Orchestrates evaluation** across distributed validators
3. **Aggregates scores** using stake-weighted consensus
4. **Submits weights** to Bittensor at epoch boundaries

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   MINERS    │ ──▶ │     PLATFORM     │ ──▶ │  BITTENSOR  │
│  (Agents)   │     │  (Load Balancer) │     │   (Weights) │
└─────────────┘     └──────────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              ┌──────────┐  ┌──────────┐
              │Challenge │  │Challenge │
              │    A     │  │    B     │
              │  (Repo)  │  │  (Repo)  │
              └──────────┘  └──────────┘
```

---

## Agent Lifecycle

### 1. Development

Develop your agent following the **challenge-specific** SDK and requirements:

```python
# Example: Terminal Bench uses term_sdk
from term_sdk import Agent, LLM

class MyAgent(Agent):
    def solve(self, task):
        # Your solution logic
        pass
```

**Check the challenge repository** for the correct SDK, imports, and patterns.

### 2. Submission

Submit your agent code to the Platform API. The submission is:
- Stored in the central database
- Compiled/validated by the challenge system
- Queued for evaluation by validators

### 3. Evaluation

Validators independently evaluate your submission:
- Each validator runs the **challenge-specific** Docker container
- Your agent executes in a sandboxed environment
- Scores are computed based on challenge criteria

### 4. Scoring

Platform aggregates validator scores:
- Stake-weighted averaging
- Outlier detection (removes anomalous validators)
- Confidence calculation

### 5. Rewards

At epoch end (~72 minutes), weights are submitted to Bittensor:
- Higher scores = higher weights = more TAO rewards
- Weights are normalized using softmax

---

## Platform API

### Endpoints

All challenge-specific endpoints are proxied through Platform:

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/bridge/{challenge_id}/submit` | Submit agent code |
| `GET /api/v1/bridge/{challenge_id}/status/{hash}` | Check submission status |
| `GET /api/v1/bridge/{challenge_id}/leaderboard` | View rankings |

### Authentication

Submissions are signed with your Bittensor hotkey:
- Use `sr25519` signature scheme
- Include timestamp to prevent replay attacks

---

## Common Questions

### Where do I find the SDK?

**In the challenge repository.** Platform itself does not provide agent SDKs.

### Why did my submission fail?

Check the challenge repository for:
- Allowed imports/packages
- Resource limits (memory, CPU, time)
- Required entry points and formats

### How are scores calculated?

Each challenge defines its own scoring algorithm. Platform only aggregates scores from validators.

### Can I test locally?

Yes, using tools from the **challenge repository**:
```bash
# Example for Terminal Bench
term test --agent my_agent.py --task task_name
```

### What's the evaluation timeout?

Defined by each challenge. Check the challenge docs for specific limits.

---

## Architecture Summary

```
Platform Repository (this repo)
├── crates/
│   ├── platform-server/     # Central coordination server
│   ├── challenge-sdk/       # SDK for building challenges (not agents!)
│   ├── challenge-orchestrator/
│   ├── bittensor-integration/
│   └── ...
└── bins/
    ├── platform/           # Server binary
    └── validator-node/     # Validator binary

Challenge Repositories (separate)
├── term-challenge/         # Terminal Bench
│   ├── sdk/               # Agent SDK (term_sdk)
│   ├── tasks/             # Task definitions
│   └── evaluation/        # Scoring logic
└── (other challenges)/
```

---

## Getting Started

1. **Choose a challenge** you want to participate in
2. **Go to that challenge's repository** (not this one)
3. **Read the challenge-specific documentation**
4. **Develop your agent** using the challenge SDK
5. **Submit** through the Platform API or challenge CLI
6. **Monitor** your submission status and leaderboard position

---

## Links

- [Platform Server](https://chain.platform.network) - Central coordination
- [Bittensor Docs](https://docs.bittensor.com) - Network documentation
- [Validator Guide](docs/validator.md) - Running a validator

For challenge-specific questions, please refer to the appropriate challenge repository.
