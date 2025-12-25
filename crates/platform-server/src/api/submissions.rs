//! Submissions API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct ListSubmissionsQuery {
    pub limit: Option<usize>,
    pub status: Option<String>,
}

pub async fn list_submissions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListSubmissionsQuery>,
) -> Result<Json<Vec<Submission>>, StatusCode> {
    let submissions = if query.status.as_deref() == Some("pending") {
        queries::get_pending_submissions(&state.db).await
    } else {
        queries::get_pending_submissions(&state.db).await
    }
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let limit = query.limit.unwrap_or(100);
    let limited: Vec<_> = submissions.into_iter().take(limit).collect();
    Ok(Json(limited))
}

pub async fn get_submission(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Submission>, StatusCode> {
    let submission = queries::get_submission(&state.db, &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(submission))
}

pub async fn get_submission_source(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let submission = queries::get_submission(&state.db, &id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(serde_json::json!({
        "agent_hash": submission.agent_hash,
        "source_code": submission.source_code,
    })))
}

pub async fn submit_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SubmitAgentRequest>,
) -> Result<Json<SubmitAgentResponse>, (StatusCode, Json<SubmitAgentResponse>)> {
    let epoch = queries::get_current_epoch(&state.db).await.unwrap_or(0);

    // Create submission with API key for centralized LLM inference
    let submission = queries::create_submission(
        &state.db,
        &req.miner_hotkey,
        &req.source_code,
        req.name.as_deref(),
        req.api_key.as_deref(),
        req.api_provider.as_deref(),
        req.api_keys_encrypted.as_deref(),
        epoch,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SubmitAgentResponse {
                success: false,
                submission_id: None,
                agent_hash: None,
                error: Some(e.to_string()),
            }),
        )
    })?;

    tracing::info!(
        "Agent submitted: {} (hash: {}) from {} with provider: {:?}",
        submission.name.as_deref().unwrap_or("unnamed"),
        &submission.agent_hash[..16],
        &req.miner_hotkey,
        req.api_provider
    );

    state
        .broadcast_event(WsEvent::SubmissionReceived(SubmissionEvent {
            submission_id: submission.id.clone(),
            agent_hash: submission.agent_hash.clone(),
            miner_hotkey: submission.miner_hotkey.clone(),
            name: submission.name.clone(),
            epoch,
        }))
        .await;

    Ok(Json(SubmitAgentResponse {
        success: true,
        submission_id: Some(submission.id),
        agent_hash: Some(submission.agent_hash),
        error: None,
    }))
}
