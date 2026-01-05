//! Validators API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::{AppState, ValidatorMetrics};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn list_validators(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<Validator>>, StatusCode> {
    let validators = queries::get_validators(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(validators))
}

pub async fn get_validator(
    State(state): State<Arc<AppState>>,
    Path(hotkey): Path<String>,
) -> Result<Json<Validator>, StatusCode> {
    let validator = queries::get_validator(&state.db, &hotkey)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(validator))
}

pub async fn register_validator(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ValidatorRegistration>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    queries::upsert_validator(&state.db, &req.hotkey, req.stake)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "error": e.to_string() })),
            )
        })?;

    state
        .broadcast_event(WsEvent::ValidatorJoined(ValidatorEvent {
            hotkey: req.hotkey.clone(),
            stake: req.stake,
        }))
        .await;

    Ok(Json(
        serde_json::json!({ "success": true, "hotkey": req.hotkey }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatRequest {
    pub hotkey: String,
    pub signature: String,
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    queries::upsert_validator(&state.db, &req.hotkey, 0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "success": true })))
}

/// Minimum stake required for whitelist (10,000 TAO in RAO)
const MIN_STAKE_FOR_WHITELIST: i64 = 10_000_000_000_000;

/// GET /api/v1/validators/whitelist - Get whitelisted validators
/// Returns validators with stake >= 10,000 TAO who connected in the last 24h
pub async fn get_whitelisted_validators(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<String>>, StatusCode> {
    let validators = queries::get_whitelisted_validators(&state.db, MIN_STAKE_FOR_WHITELIST)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(validators))
}

/// Request to report validator metrics
#[derive(Debug, serde::Deserialize)]
pub struct MetricsReportRequest {
    pub hotkey: String,
    pub signature: String,
    pub timestamp: i64,
    pub cpu_percent: f32,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
}

/// Response for validator stats
#[derive(Debug, serde::Serialize)]
pub struct ValidatorsStatsResponse {
    pub validators: Vec<ValidatorWithMetrics>,
    pub total_active: i32,
    pub average_cpu_percent: f32,
    pub average_memory_percent: f32,
}

/// Validator info with optional metrics
#[derive(Debug, serde::Serialize)]
pub struct ValidatorWithMetrics {
    pub hotkey: String,
    pub stake: i64,
    pub last_seen: Option<i64>,
    pub is_active: bool,
    pub metrics: Option<ValidatorMetrics>,
}

/// POST /api/v1/validators/metrics - Validator reports system metrics
pub async fn report_metrics(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MetricsReportRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use crate::api::auth::verify_signature;

    // Verify signature
    let message = format!("metrics:{}:{}", req.hotkey, req.timestamp);
    if !verify_signature(&req.hotkey, &message, &req.signature) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify timestamp (within 1 minute)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if (now - req.timestamp).abs() > 60 {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Store in cache
    state.metrics_cache.update(
        &req.hotkey,
        ValidatorMetrics {
            cpu_percent: req.cpu_percent,
            memory_used_mb: req.memory_used_mb,
            memory_total_mb: req.memory_total_mb,
            timestamp: req.timestamp,
        },
    );

    tracing::debug!(
        hotkey = %req.hotkey,
        cpu = %req.cpu_percent,
        mem_mb = %req.memory_used_mb,
        "Received validator metrics"
    );

    Ok(Json(serde_json::json!({"success": true})))
}

/// GET /api/v1/validators/stats - Get all validators with their metrics
pub async fn get_validators_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ValidatorsStatsResponse>, StatusCode> {
    // Get all validators from DB
    let validators = queries::list_validators(&state.db).await.map_err(|e| {
        tracing::error!("Failed to list validators: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Get cached metrics
    let all_metrics = state.metrics_cache.get_all();
    let metrics_map: std::collections::HashMap<String, ValidatorMetrics> =
        all_metrics.into_iter().collect();

    // Combine validators with metrics
    let mut result = Vec::new();
    let mut total_cpu = 0.0f32;
    let mut total_mem_percent = 0.0f32;
    let mut metrics_count = 0;

    for v in validators {
        let metrics = metrics_map.get(&v.hotkey).cloned();
        if let Some(ref m) = metrics {
            total_cpu += m.cpu_percent;
            if m.memory_total_mb > 0 {
                total_mem_percent += (m.memory_used_mb as f32 / m.memory_total_mb as f32) * 100.0;
            }
            metrics_count += 1;
        }
        result.push(ValidatorWithMetrics {
            hotkey: v.hotkey,
            stake: v.stake,
            last_seen: v.last_seen.map(|dt| dt.and_utc().timestamp()),
            is_active: v.is_active,
            metrics,
        });
    }

    Ok(Json(ValidatorsStatsResponse {
        total_active: result.iter().filter(|v| v.is_active).count() as i32,
        average_cpu_percent: if metrics_count > 0 {
            total_cpu / metrics_count as f32
        } else {
            0.0
        },
        average_memory_percent: if metrics_count > 0 {
            total_mem_percent / metrics_count as f32
        } else {
            0.0
        },
        validators: result,
    }))
}
