//! Challenges API handlers

use crate::db::queries;
use crate::models::*;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

pub async fn get_network_state(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NetworkStateEvent>, StatusCode> {
    let current_epoch = queries::get_current_epoch(&state.db).await.unwrap_or(0);
    let current_block = queries::get_network_state(&state.db, "current_block")
        .await
        .unwrap_or(None)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0u64);
    let total_stake = queries::get_total_stake(&state.db).await.unwrap_or(0);
    let validators = queries::get_validators(&state.db).await.unwrap_or_default();
    let pending = queries::get_pending_submissions(&state.db)
        .await
        .unwrap_or_default();

    Ok(Json(NetworkStateEvent {
        current_epoch,
        current_block,
        total_stake,
        active_validators: validators.len() as u32,
        pending_submissions: pending.len() as u32,
    }))
}
