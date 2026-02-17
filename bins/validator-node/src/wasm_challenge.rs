use anyhow::{Context, Result};
use platform_challenge_registry::RegisteredChallenge;
use platform_challenge_sdk_wasm::{EvaluationInput, EvaluationOutput};
use platform_core::{ChallengeId, Keypair};
use platform_p2p_consensus::{EvaluationRecord, StateManager, ValidatorEvaluation};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use wasm_runtime_interface::{
    InstanceConfig, NetworkPolicy, RuntimeConfig, WasmModule, WasmRuntime,
};

pub struct WasmChallengeExecutor {
    runtime: WasmRuntime,
    modules: HashMap<ChallengeId, WasmModule>,
    wasm_dir: PathBuf,
    validator_id: String,
}

impl WasmChallengeExecutor {
    pub fn new(wasm_dir: PathBuf, validator_id: String) -> Result<Self> {
        let config = RuntimeConfig::default();
        let runtime = WasmRuntime::new(config).context("failed to create WASM runtime")?;
        std::fs::create_dir_all(&wasm_dir).context("failed to create WASM module directory")?;
        Ok(Self {
            runtime,
            modules: HashMap::new(),
            wasm_dir,
            validator_id,
        })
    }

    pub fn load_module(&mut self, challenge_id: ChallengeId, wasm_bytes: &[u8]) -> Result<()> {
        let module = self
            .runtime
            .compile_module(wasm_bytes)
            .context("failed to compile WASM module")?;
        self.modules.insert(challenge_id, module);
        info!(challenge_id = %challenge_id, "WASM module compiled and cached");
        Ok(())
    }

    pub fn load_module_from_path(&mut self, challenge_id: ChallengeId, path: &Path) -> Result<()> {
        let wasm_bytes =
            std::fs::read(path).with_context(|| format!("failed to read WASM file: {:?}", path))?;
        self.load_module(challenge_id, &wasm_bytes)
    }

    pub fn load_module_from_registry(&mut self, registered: &RegisteredChallenge) -> Result<()> {
        let wasm_meta = registered
            .entry
            .wasm_module
            .as_ref()
            .context("challenge has no WASM module configured")?;

        let module_path = if Path::new(&wasm_meta.module_location).is_absolute() {
            PathBuf::from(&wasm_meta.module_location)
        } else {
            self.wasm_dir.join(&wasm_meta.module_location)
        };

        let wasm_bytes = std::fs::read(&module_path)
            .with_context(|| format!("failed to read WASM file: {:?}", module_path))?;

        if !wasm_meta.module_hash.is_empty() && !wasm_meta.verify_hash(&wasm_bytes) {
            anyhow::bail!(
                "WASM module hash mismatch for challenge {}",
                registered.entry.id
            );
        }

        self.load_module(registered.entry.id, &wasm_bytes)
    }

    pub fn has_module(&self, challenge_id: &ChallengeId) -> bool {
        self.modules.contains_key(challenge_id)
    }

    pub fn evaluate(
        &self,
        challenge_id: &ChallengeId,
        input: &EvaluationInput,
        network_policy: NetworkPolicy,
    ) -> Result<EvaluationOutput> {
        let module = self
            .modules
            .get(challenge_id)
            .with_context(|| format!("no compiled module for challenge {}", challenge_id))?;

        let instance_config = InstanceConfig {
            network_policy,
            challenge_id: challenge_id.to_string(),
            validator_id: self.validator_id.clone(),
            ..Default::default()
        };

        let mut instance = self
            .runtime
            .instantiate(module, instance_config, None)
            .context("failed to instantiate WASM module")?;

        let input_bytes =
            bincode::serialize(input).context("failed to serialize EvaluationInput")?;

        let alloc_result = instance
            .call("alloc", &[wasmtime::Val::I32(input_bytes.len() as i32)])
            .context("failed to call alloc")?;
        let input_ptr = match alloc_result.first() {
            Some(wasmtime::Val::I32(ptr)) => *ptr,
            _ => anyhow::bail!("alloc returned unexpected type"),
        };

        if input_ptr == 0 {
            anyhow::bail!("WASM alloc returned null pointer");
        }

        instance
            .write_memory(input_ptr as usize, &input_bytes)
            .context("failed to write input to WASM memory")?;

        let packed = instance
            .call_i32_i32_return_i64("evaluate", input_ptr, input_bytes.len() as i32)
            .context("failed to call evaluate")?;

        let out_len = (packed >> 32) as u32;
        let out_ptr = (packed & 0xFFFF_FFFF) as u32;

        if out_ptr == 0 && out_len == 0 {
            anyhow::bail!("WASM evaluate returned null result");
        }

        let output_bytes = instance
            .read_memory(out_ptr as usize, out_len as usize)
            .context("failed to read evaluation output from WASM memory")?;

        let output: EvaluationOutput = bincode::deserialize(&output_bytes)
            .context("failed to deserialize EvaluationOutput")?;

        debug!(
            challenge_id = %challenge_id,
            score = output.score,
            valid = output.valid,
            "WASM evaluation complete"
        );

        Ok(output)
    }

    pub fn evaluate_submissions(
        &self,
        challenge_id: &ChallengeId,
        records: &[EvaluationRecord],
        network_policy: NetworkPolicy,
        keypair: &Keypair,
        state_manager: &Arc<StateManager>,
    ) {
        let validator_hotkey = keypair.hotkey();
        let stake = state_manager.read(|state| {
            state
                .validators
                .get(&validator_hotkey)
                .copied()
                .unwrap_or(0)
        });

        for record in records {
            if record.challenge_id != *challenge_id {
                continue;
            }
            if record.finalized {
                continue;
            }
            if record.evaluations.contains_key(&validator_hotkey) {
                continue;
            }

            let input = EvaluationInput {
                agent_data: record.agent_hash.as_bytes().to_vec(),
                challenge_id: challenge_id.to_string(),
                params: Vec::new(),
            };

            let score = match self.evaluate(challenge_id, &input, network_policy.clone()) {
                Ok(output) => {
                    if output.valid {
                        (output.score as f64) / 10000.0
                    } else {
                        0.0
                    }
                }
                Err(e) => {
                    error!(
                        challenge_id = %challenge_id,
                        submission_id = %record.submission_id,
                        error = %e,
                        "WASM evaluation failed"
                    );
                    continue;
                }
            };

            let score = score.clamp(0.0, 1.0);
            let timestamp = chrono::Utc::now().timestamp_millis();

            #[derive(serde::Serialize)]
            struct EvaluationSigningData<'a> {
                submission_id: &'a str,
                score: f64,
            }

            let signing_data = EvaluationSigningData {
                submission_id: &record.submission_id,
                score,
            };

            let signing_bytes = match bincode::serialize(&signing_data) {
                Ok(b) => b,
                Err(e) => {
                    error!(
                        submission_id = %record.submission_id,
                        error = %e,
                        "failed to serialize signing data"
                    );
                    continue;
                }
            };

            let signature = match keypair.sign_bytes(&signing_bytes) {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        submission_id = %record.submission_id,
                        error = %e,
                        "failed to sign evaluation"
                    );
                    continue;
                }
            };

            let evaluation = ValidatorEvaluation {
                score,
                stake,
                timestamp,
                signature: signature.clone(),
            };

            let result = state_manager.apply(|state| {
                state.add_validator_evaluation(
                    &record.submission_id,
                    validator_hotkey.clone(),
                    evaluation,
                    &signature,
                )
            });

            match result {
                Ok(()) => {
                    info!(
                        submission_id = %record.submission_id,
                        challenge_id = %challenge_id,
                        score = score,
                        "WASM evaluation score submitted"
                    );
                }
                Err(e) => {
                    warn!(
                        submission_id = %record.submission_id,
                        error = %e,
                        "failed to add validator evaluation to state"
                    );
                }
            }
        }
    }
}
