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

## Completed Refactoring

1. **ExecPolicy added to core** (`crates/core/src/challenge.rs`)
   - New `ExecPolicy` struct with `resource_limits`, `network_policy`, `max_concurrent_instances`, and `deterministic` fields.
   - `WasmChallengeConfig` now includes `exec_policy: ExecPolicy` (with `#[serde(default)]` for backward compatibility).
   - `From<&Challenge>` impl populates `exec_policy` from WASM metadata.

2. **P2P consensus state updated** (`crates/p2p-consensus/src/state.rs`)
   - `ChallengeConfig` now includes WASM fields: `wasm_module_hash`, `wasm_module_path`, `wasm_entrypoint`, `wasm_network_policy` (all `Option` with `#[serde(default)]`).

3. **Registry is WASM-first** (`crates/challenge-registry/src/registry.rs`)
   - `ChallengeEntry::new()` deprecated in favor of `ChallengeEntry::new_wasm()`.
   - `ChallengeRegistry::register()` warns on Docker-only registrations.
   - `ChallengeRegistry::list_wasm_ready()` filters for WASM-capable challenges.

4. **Discovery computes WASM hashes** (`crates/challenge-registry/src/discovery.rs`)
   - `DiscoveredChallenge` includes `wasm_module_hash: Option<String>`.
   - `discover_from_wasm_dir()` computes SHA-256 hash of discovered `.wasm` files.

5. **Validator node has WASM runtime dependency** (`bins/validator-node/Cargo.toml`)
   - `wasm-runtime-interface` added as a dependency for future WASM execution integration.

6. **Challenge orchestrator deprecated** (`crates/challenge-orchestrator/`)
   - Module-level `#![deprecated]` annotation added to `lib.rs`.
   - Docker module marked as deprecated in doc comments.
   - Crate remains excluded from workspace (not compiled).

## Remaining Follow-up Items

1. **Remove Docker fallback in orchestrator**
   - `backend.rs` should return error if broker is unavailable unless explicit dev mode.
2. **Integrate WASM execution into validator node**
   - Wire `wasm-runtime-interface` into the validator evaluation flow.
3. **Remove hardcoded challenge Docker names**
   - `cleanup_stale_task_containers` in `challenge-orchestrator` has hardcoded `term-challenge-` prefixes.
4. **Full Docker removal**
   - Once WASM-first is validated in production, remove `docker_image` fields from `ChallengeEntry` and `DiscoveredChallenge`.
