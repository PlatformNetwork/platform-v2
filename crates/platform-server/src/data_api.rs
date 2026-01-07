//! Data API - Gateway to all databases with Claim/Lease primitives
//!
//! This module implements the Data API as described in the architecture:
//! - Structured reads and writes
//! - Claim/Lease coordination primitives (anti-duplication)
//! - Snapshot endpoint for deterministic weight calculation
//!
//! Invariants:
//! - A task can be owned by only one validator at a time
//! - Challenges access DB only through this API
//! - All rules are enforced server-side

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ============================================================================
// TASK CLAIM/LEASE (Anti-Duplication Mechanism)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListTasksQuery {
    pub limit: Option<usize>,
}

/// List available tasks (pending submissions that need evaluation)
pub async fn list_tasks(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListTasksQuery>,
) -> Result<Json<Vec<Submission>>, StatusCode> {
    let tasks = queries::get_pending_submissions(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let limit = query.limit.unwrap_or(100);
    let limited: Vec<_> = tasks.into_iter().take(limit).collect();
    Ok(Json(limited))
}

/// Claim a task for exclusive processing (atomic operation)
/// Returns None if task is already claimed by another validator
pub async fn claim_task(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ClaimTaskRequest>,
) -> Result<Json<ClaimTaskResponse>, StatusCode> {
    let lease = queries::claim_task(
        &state.db,
        &req.task_id,
        &req.validator_hotkey,
        req.ttl_seconds,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(ref l) = lease {
        // Broadcast claim event
        state
            .broadcast_event(WsEvent::TaskClaimed(TaskClaimedEvent {
                task_id: req.task_id.clone(),
                validator_hotkey: req.validator_hotkey.clone(),
                expires_at: l.expires_at,
            }))
            .await;

        info!("Task {} claimed by {}", req.task_id, req.validator_hotkey);
    }

    Ok(Json(ClaimTaskResponse {
        success: lease.is_some(),
        lease,
        error: None,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RenewRequest {
    pub validator_hotkey: String,
    #[allow(dead_code)] // Kept for API compatibility
    pub signature: String,
    pub ttl_seconds: u64,
}

/// Renew an existing task lease
pub async fn renew_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
    Json(req): Json<RenewRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let success = queries::renew_task(&state.db, &task_id, &req.validator_hotkey, req.ttl_seconds)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "success": success })))
}

#[derive(Debug, Deserialize)]
pub struct AckRequest {
    pub validator_hotkey: String,
    #[allow(dead_code)] // Kept for API compatibility
    pub signature: String,
}

/// Acknowledge task completion (marks task as done)
pub async fn ack_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
    Json(req): Json<AckRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let success = queries::ack_task(&state.db, &task_id, &req.validator_hotkey)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if success {
        info!("Task {} acknowledged by {}", task_id, req.validator_hotkey);
    }

    Ok(Json(serde_json::json!({ "success": success })))
}

#[derive(Debug, Deserialize)]
pub struct FailRequest {
    pub validator_hotkey: String,
    #[allow(dead_code)] // Kept for API compatibility
    pub signature: String,
    pub reason: Option<String>,
}

/// Mark task as failed (releases lease for others to claim)
pub async fn fail_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<String>,
    Json(req): Json<FailRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let success = queries::fail_task(
        &state.db,
        &task_id,
        &req.validator_hotkey,
        req.reason.as_deref(),
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({ "success": success })))
}

// ============================================================================
// RESULTS (Write evaluation results)
// ============================================================================

/// Write evaluation result to database
/// Called by challenge containers after evaluating an agent
pub async fn write_result(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WriteResultRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Get submission by agent_hash to get submission_id
    let submission = queries::get_submission_by_hash(&state.db, &req.agent_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let eval_req = SubmitEvaluationRequest {
        submission_id: submission.id,
        agent_hash: req.agent_hash.clone(),
        validator_hotkey: req.validator_hotkey.clone(),
        signature: req.signature.clone(),
        score: req.score,
        tasks_passed: 0,
        tasks_total: 0,
        tasks_failed: 0,
        total_cost_usd: 0.0,
        execution_time_ms: req.execution_time_ms,
        task_results: req.task_results,
        execution_log: None,
    };

    let evaluation = queries::create_evaluation(&state.db, &eval_req)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update leaderboard
    let _ = queries::update_leaderboard(&state.db, &req.agent_hash).await;

    Ok(Json(serde_json::json!({
        "success": true,
        "evaluation_id": evaluation.id,
    })))
}

/// Get evaluation results for an agent
pub async fn get_results(
    State(state): State<Arc<AppState>>,
    Path(agent_hash): Path<String>,
) -> Result<Json<Vec<Evaluation>>, StatusCode> {
    let results = queries::get_evaluations_for_agent(&state.db, &agent_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(results))
}

// ============================================================================
// SNAPSHOT (For /get_weights deterministic calculation)
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct SnapshotQuery {
    pub epoch: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SnapshotResponse {
    pub epoch: u64,
    pub snapshot_time: i64,
    pub leaderboard: Vec<LeaderboardEntry>,
    pub validators: Vec<Validator>,
    pub total_stake: u64,
}

/// Get database snapshot for deterministic weight calculation
///
/// This endpoint provides all data needed for /get_weights:
/// - Current epoch
/// - Leaderboard with consensus scores
/// - Active validators and their stakes
///
/// Challenges MUST use this snapshot (not live queries) to ensure
/// all validators compute identical weights.
pub async fn get_snapshot(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SnapshotQuery>,
) -> Result<Json<SnapshotResponse>, StatusCode> {
    let current_epoch = queries::get_current_epoch(&state.db).await.unwrap_or(0);
    let epoch = query.epoch.unwrap_or(current_epoch);

    let leaderboard = queries::get_leaderboard(&state.db, 1000)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let validators = queries::get_validators(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_stake = queries::get_total_stake(&state.db).await.unwrap_or(0);

    Ok(Json(SnapshotResponse {
        epoch,
        snapshot_time: now(),
        leaderboard,
        validators,
        total_stake,
    }))
}
