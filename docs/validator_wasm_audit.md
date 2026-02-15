# Validator/Core/P2P/WASM Audit Notes

## Scope

Reviewed: `bins/validator-node`, `crates/core`, `crates/p2p-consensus`, `crates/challenge-orchestrator`, `crates/challenge-registry`, `crates/wasm-runtime-interface`.

## Key Findings

### Validator Node
- `bins/validator-node` still wires consensus + storage, but no orchestrator usage. Challenge execution appears absent from validator node runtime path; any future WASM path needs explicit integration.
- CLI flags include `--docker-challenges` with default `true` but no usage beyond argument definition. This remains legacy from Docker challenge flow; production is WASM-first.

### Challenge Orchestrator (Test Harness)
- `crates/challenge-orchestrator` is centered on Docker container lifecycle. It is intended for test harness usage only.
- Backend selection uses secure broker if available, otherwise **falls back to direct Docker**, even when `DEVELOPMENT_MODE` is not set (`BackendMode::Fallback`), with warnings. This is a centralized fallback path that conflicts with P2P/secure expectations.
- Docker-only notions appear in:
  - `ChallengeContainerConfig` usage (core) and `ChallengeInstance` container ID/endpoint metadata.
  - `refresh_challenge` uses a synthesized config with hardcoded defaults (mechanism_id=0, timeout, CPU/mem). This bypasses canonical config/state.
  - `cleanup_stale_task_containers` has hardcoded `term-challenge-` prefixes and container exclusions.

### Challenge Registry
- Registry entries still require a `docker_image` field and only optionally include WASM metadata. This is a legacy docker-first structure that needs inversion for WASM-first.
- `discovery` supports docker registry and local path scanning with placeholders; P2P discovery is toggled but no concrete implementation. This may be a legacy/unused path.

### Core State
- `core::ChainState` includes legacy `challenges` (full challenge with `wasm_code`), Docker `challenge_configs`, and WASM `wasm_challenge_configs` in parallel.
- There is overlap/duplication between `core::ChallengeConfig`, `core::ChallengeContainerConfig`, and `p2p-consensus::ChallengeConfig` (docker image). The Docker config and docker image in p2p consensus state are likely legacy for container evaluation.

### P2P Consensus
- `p2p-consensus::ChainState` stores `ChallengeConfig` with `docker_image` and weight allocation. This is incompatible with WASM-only execution and is likely legacy from container-based challenge evaluation.
- Consensus engine is PBFT-style and uses validator stake data from `ValidatorSet`. Stake is taken from heartbeats unless verified stake is set (metagraph refresh uses `set_verified_stake`), which is a potential gap if verified stakes are not enforced.

### WASM Runtime Interface
- Runtime is strict and well-structured: `NetworkPolicy` with validation, explicit host functions, request limits, and audit log hooks.
- No apparent recursion; resource caps are enforced via wasmtime `StoreLimits` and request limits.
- No apparent integration with validator node yet (outside scope), but runtime interface is ready to be plumbed into execution path.

## Cleanup / Follow-up Recommendations

1. **Remove Docker fallback in orchestrator**
   - `backend.rs` should return error if broker is unavailable unless explicit dev mode. Today it falls back even when not in dev mode (`BackendMode::Fallback`).
2. **Deprecate or remove docker-first flags/structs**
   - `validator-node` `--docker-challenges` flag appears unused; remove or wire into explicit Docker-only flows.
   - Evaluate removing `ChallengeContainerConfig` usage, `challenge-orchestrator` crate, and docker image references once WASM-first path is in place.
3. **Unify challenge configs**
   - Collapse legacy Docker configs in `core::ChainState` and `p2p-consensus::ChainState` to WASM-only representations with `WasmChallengeConfig` metadata and network policy.
4. **Registry must become WASM-first**
   - `ChallengeEntry` should store WASM module metadata as primary, with docker fields removed or optional legacy for migration.
   - `discovery` should focus on WASM module registry or signed P2P announcements instead of docker registry scanning.
5. **Remove hardcoded challenge Docker names**
   - `cleanup_stale_task_containers` in `challenge-orchestrator` has hardcoded `term-challenge-` and should be removed or generalized.
6. **Consensus state challenge metadata**
   - Replace `p2p-consensus::ChallengeConfig` docker image with WASM module metadata (hash/path/entrypoint/policy) to support WASM-only evaluation.

## Suggested Next Steps

- Determine removal strategy for Docker orchestrator (remove or gate behind dev-only compile feature).
- Integrate WASM runtime execution into validator flow and consensus state.
- Align registry and core state to store WASM metadata only, with migration of existing state.
