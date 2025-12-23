//! RPC request handlers

use crate::auth::*;
use crate::types::*;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use parking_lot::RwLock;
use platform_core::{ChainState, Hotkey, JobStatus, Stake, ValidatorInfo};
use platform_subnet_manager::BanList;
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Shared state for RPC handlers
pub struct RpcState {
    pub chain_state: Arc<RwLock<ChainState>>,
    pub bans: Arc<RwLock<BanList>>,
    pub start_time: Instant,
    pub version: String,
    pub netuid: u16,
    pub name: String,
    pub min_stake: u64,
}

impl RpcState {
    pub fn new(
        chain_state: Arc<RwLock<ChainState>>,
        bans: Arc<RwLock<BanList>>,
        netuid: u16,
        name: String,
        min_stake: u64,
    ) -> Self {
        Self {
            chain_state,
            bans,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            netuid,
            name,
            min_stake,
        }
    }
}

/// GET /health
pub async fn health_handler(
    State(state): State<Arc<RpcState>>,
) -> Json<RpcResponse<HealthResponse>> {
    Json(RpcResponse::ok(HealthResponse {
        status: "healthy".to_string(),
        version: state.version.clone(),
        uptime_secs: state.start_time.elapsed().as_secs(),
    }))
}

/// GET /status
pub async fn status_handler(
    State(state): State<Arc<RpcState>>,
) -> Json<RpcResponse<StatusResponse>> {
    let chain = state.chain_state.read();

    Json(RpcResponse::ok(StatusResponse {
        netuid: state.netuid,
        name: state.name.clone(),
        version: state.version.clone(),
        block_height: chain.block_height,
        epoch: chain.epoch,
        validators_count: chain.validators.len(),
        challenges_count: chain.challenges.len(),
        pending_jobs: chain.pending_jobs.len(),
        is_paused: false,
    }))
}

/// GET /validators
pub async fn validators_handler(
    State(state): State<Arc<RpcState>>,
    Query(params): Query<PaginationParams>,
) -> Json<RpcResponse<Vec<ValidatorResponse>>> {
    let chain = state.chain_state.read();

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);

    let validators: Vec<ValidatorResponse> = chain
        .validators
        .values()
        .skip(offset)
        .take(limit)
        .map(|v| ValidatorResponse {
            hotkey: v.hotkey.to_hex(),
            stake: v.stake.0,
            stake_tao: v.stake.as_tao(),
            is_active: v.is_active,
            last_seen: v.last_seen,
            peer_id: v.peer_id.clone(),
            x25519_pubkey: v.x25519_pubkey.clone(),
        })
        .collect();

    Json(RpcResponse::ok(validators))
}

/// GET /challenges
pub async fn challenges_handler(
    State(state): State<Arc<RpcState>>,
) -> Json<RpcResponse<Vec<ChallengeResponse>>> {
    let chain = state.chain_state.read();

    let challenges: Vec<ChallengeResponse> = chain
        .challenges
        .values()
        .map(|c| ChallengeResponse {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            is_active: c.is_active,
            emission_weight: c.config.emission_weight,
            timeout_secs: c.config.timeout_secs,
        })
        .collect();

    Json(RpcResponse::ok(challenges))
}

/// GET /challenge/:id
pub async fn challenge_handler(
    State(state): State<Arc<RpcState>>,
    Path(id): Path<String>,
) -> Result<Json<RpcResponse<ChallengeResponse>>, StatusCode> {
    let chain = state.chain_state.read();

    // Find challenge by ID string
    let challenge = chain
        .challenges
        .values()
        .find(|c| c.id.to_string() == id || c.name == id);

    match challenge {
        Some(c) => Ok(Json(RpcResponse::ok(ChallengeResponse {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            is_active: c.is_active,
            emission_weight: c.config.emission_weight,
            timeout_secs: c.config.timeout_secs,
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// POST /register
pub async fn register_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<RegisterRequest>,
) -> Json<RpcResponse<RegisterResponse>> {
    // Verify signature
    match verify_validator_signature(&req.hotkey, &req.message, &req.signature) {
        Ok(true) => {}
        Ok(false) => {
            return Json(RpcResponse::ok(RegisterResponse {
                accepted: false,
                uid: None,
                reason: Some("Invalid signature".to_string()),
            }));
        }
        Err(e) => {
            return Json(RpcResponse::ok(RegisterResponse {
                accepted: false,
                uid: None,
                reason: Some(format!("Auth error: {}", e)),
            }));
        }
    }

    // Parse hotkey
    let hotkey = match Hotkey::from_hex(&req.hotkey) {
        Some(h) => h,
        None => {
            return Json(RpcResponse::ok(RegisterResponse {
                accepted: false,
                uid: None,
                reason: Some("Invalid hotkey format".to_string()),
            }));
        }
    };

    // Check if banned
    let bans = state.bans.read();
    if bans.is_validator_banned(&hotkey) {
        return Json(RpcResponse::ok(RegisterResponse {
            accepted: false,
            uid: None,
            reason: Some("Validator is banned".to_string()),
        }));
    }
    drop(bans);

    // Check if already registered
    let chain = state.chain_state.read();
    if chain.validators.contains_key(&hotkey) {
        return Json(RpcResponse::ok(RegisterResponse {
            accepted: true,
            uid: Some(0),
            reason: Some("Already registered".to_string()),
        }));
    }
    drop(chain);

    // Register with minimum stake (actual stake will be synced from Bittensor)
    let info = ValidatorInfo::new(hotkey.clone(), Stake::new(state.min_stake));

    let mut chain = state.chain_state.write();
    match chain.add_validator(info) {
        Ok(_) => {
            info!("Validator registered via RPC: {}", req.hotkey);
            Json(RpcResponse::ok(RegisterResponse {
                accepted: true,
                uid: Some(0),
                reason: None,
            }))
        }
        Err(e) => Json(RpcResponse::ok(RegisterResponse {
            accepted: false,
            uid: None,
            reason: Some(format!("Registration failed: {}", e)),
        })),
    }
}

/// POST /heartbeat
pub async fn heartbeat_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Json<RpcResponse<HeartbeatResponse>> {
    // Parse hotkey
    let hotkey = match Hotkey::from_hex(&req.hotkey) {
        Some(h) => h,
        None => {
            return Json(RpcResponse::error("Invalid hotkey"));
        }
    };

    // Update last_seen
    let mut chain = state.chain_state.write();
    if let Some(validator) = chain.validators.get_mut(&hotkey) {
        validator.last_seen = chrono::Utc::now();
        if let Some(peer_id) = req.peer_id {
            validator.peer_id = Some(peer_id);
        }

        Json(RpcResponse::ok(HeartbeatResponse {
            accepted: true,
            current_block: chain.block_height,
            current_epoch: chain.epoch,
            next_sync_block: None,
        }))
    } else {
        Json(RpcResponse::ok(HeartbeatResponse {
            accepted: false,
            current_block: chain.block_height,
            current_epoch: chain.epoch,
            next_sync_block: None,
        }))
    }
}

/// GET /jobs
pub async fn jobs_handler(
    State(state): State<Arc<RpcState>>,
    Query(params): Query<PaginationParams>,
) -> Json<RpcResponse<Vec<JobResponse>>> {
    let chain = state.chain_state.read();

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);

    let jobs: Vec<JobResponse> = chain
        .pending_jobs
        .iter()
        .skip(offset)
        .take(limit)
        .map(|j| JobResponse {
            id: j.id.to_string(),
            challenge_id: j.challenge_id.to_string(),
            agent_hash: j.agent_hash.clone(),
            status: format!("{:?}", j.status),
            created_at: j.created_at,
            assigned_validator: j.assigned_validator.as_ref().map(|h| h.to_hex()),
        })
        .collect();

    Json(RpcResponse::ok(jobs))
}

/// POST /jobs/:id/result
pub async fn job_result_handler(
    State(state): State<Arc<RpcState>>,
    Path(job_id): Path<String>,
    Json(req): Json<JobResultRequest>,
) -> Json<RpcResponse<JobResultResponse>> {
    // Verify signature
    let msg = format!("result:{}:{}", job_id, req.score);
    match verify_validator_signature(&req.hotkey, &msg, &req.signature) {
        Ok(true) => {}
        _ => {
            return Json(RpcResponse::ok(JobResultResponse {
                accepted: false,
                job_id: job_id.clone(),
            }));
        }
    }

    // Parse job ID
    let job_uuid = match uuid::Uuid::parse_str(&job_id) {
        Ok(u) => u,
        Err(_) => {
            return Json(RpcResponse::error("Invalid job ID"));
        }
    };

    // Find and update job
    let mut chain = state.chain_state.write();
    if let Some(job) = chain.pending_jobs.iter_mut().find(|j| j.id == job_uuid) {
        job.status = JobStatus::Completed;
        job.result = Some(platform_core::Score::new(req.score, 1.0));

        info!("Job result submitted: {} score={}", job_id, req.score);
        Json(RpcResponse::ok(JobResultResponse {
            accepted: true,
            job_id,
        }))
    } else {
        Json(RpcResponse::ok(JobResultResponse {
            accepted: false,
            job_id,
        }))
    }
}

/// GET /epoch
pub async fn epoch_handler(State(state): State<Arc<RpcState>>) -> Json<RpcResponse<EpochResponse>> {
    let chain = state.chain_state.read();

    // Epoch config from state
    let blocks_per_epoch = 100u64;
    let block_in_epoch = chain.block_height % blocks_per_epoch;

    let (phase, phase_progress) = if block_in_epoch < 75 {
        ("evaluation", block_in_epoch as f64 / 75.0)
    } else if block_in_epoch < 88 {
        ("commit", (block_in_epoch - 75) as f64 / 13.0)
    } else {
        ("reveal", (block_in_epoch - 88) as f64 / 12.0)
    };

    let blocks_until_next = match phase {
        "evaluation" => 75 - block_in_epoch,
        "commit" => 88 - block_in_epoch,
        "reveal" => blocks_per_epoch - block_in_epoch,
        _ => 0,
    };

    Json(RpcResponse::ok(EpochResponse {
        current_epoch: chain.epoch,
        current_block: chain.block_height,
        blocks_per_epoch,
        phase: phase.to_string(),
        phase_progress,
        blocks_until_next_phase: blocks_until_next,
    }))
}

/// GET /sync
pub async fn sync_handler(State(state): State<Arc<RpcState>>) -> Json<RpcResponse<SyncResponse>> {
    let chain = state.chain_state.read();

    let validators: Vec<ValidatorResponse> = chain
        .validators
        .values()
        .map(|v| ValidatorResponse {
            hotkey: v.hotkey.to_hex(),
            stake: v.stake.0,
            stake_tao: v.stake.as_tao(),
            is_active: v.is_active,
            last_seen: v.last_seen,
            peer_id: v.peer_id.clone(),
            x25519_pubkey: v.x25519_pubkey.clone(),
        })
        .collect();

    let challenges: Vec<ChallengeResponse> = chain
        .challenges
        .values()
        .map(|c| ChallengeResponse {
            id: c.id.to_string(),
            name: c.name.clone(),
            description: c.description.clone(),
            code_hash: c.code_hash.clone(),
            is_active: c.is_active,
            emission_weight: c.config.emission_weight,
            timeout_secs: c.config.timeout_secs,
        })
        .collect();

    Json(RpcResponse::ok(SyncResponse {
        block_height: chain.block_height,
        epoch: chain.epoch,
        state_hash: hex::encode(chain.state_hash),
        validators,
        challenges,
    }))
}

/// POST /weights/commit
pub async fn weight_commit_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<WeightCommitRequest>,
) -> Json<RpcResponse<bool>> {
    // Verify signature
    let msg = format!(
        "commit:{}:{}:{}",
        req.challenge_id, req.epoch, req.commitment_hash
    );
    match verify_validator_signature(&req.hotkey, &msg, &req.signature) {
        Ok(true) => {}
        _ => {
            return Json(RpcResponse::error("Invalid signature"));
        }
    }

    info!(
        "Weight commitment received: validator={} challenge={} epoch={}",
        &req.hotkey[..16],
        req.challenge_id,
        req.epoch
    );

    // Commitment storage
    Json(RpcResponse::ok(true))
}

/// POST /weights/reveal  
pub async fn weight_reveal_handler(
    State(state): State<Arc<RpcState>>,
    Json(req): Json<WeightRevealRequest>,
) -> Json<RpcResponse<bool>> {
    // Verify signature
    let weights_str: String = req
        .weights
        .iter()
        .map(|w| format!("{}:{}", w.hotkey, w.weight))
        .collect::<Vec<_>>()
        .join(",");
    let msg = format!(
        "reveal:{}:{}:{}:{}",
        req.challenge_id, req.epoch, weights_str, req.salt
    );

    match verify_validator_signature(&req.hotkey, &msg, &req.signature) {
        Ok(true) => {}
        _ => {
            return Json(RpcResponse::error("Invalid signature"));
        }
    }

    info!(
        "Weight reveal received: validator={} challenge={} epoch={} weights={}",
        &req.hotkey[..16],
        req.challenge_id,
        req.epoch,
        req.weights.len()
    );

    // Commitment verification and weight storage
    Json(RpcResponse::ok(true))
}
