//! Authentication API handlers

use crate::models::*;
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, Json};
use sp_core::{crypto::Pair as _, crypto::Ss58Codec, sr25519};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use uuid::Uuid;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub async fn authenticate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<AuthResponse>)> {
    let current_time = now();
    if (current_time - req.timestamp).abs() > 300 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthResponse {
                success: false,
                token: None,
                expires_at: None,
                error: Some("Timestamp too old or in future".to_string()),
            }),
        ));
    }

    let message = format!("auth:{}:{}:{:?}", req.hotkey, req.timestamp, req.role);

    if !verify_signature(&req.hotkey, &message, &req.signature) {
        warn!("Invalid signature for auth request from {}", req.hotkey);
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthResponse {
                success: false,
                token: None,
                expires_at: None,
                error: Some("Invalid signature".to_string()),
            }),
        ));
    }

    if req.role == AuthRole::Owner && !state.is_owner(&req.hotkey) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthResponse {
                success: false,
                token: None,
                expires_at: None,
                error: Some("Not authorized as owner".to_string()),
            }),
        ));
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = current_time + 3600;

    let session = AuthSession {
        hotkey: req.hotkey.clone(),
        role: req.role.clone(),
        expires_at,
    };
    state.sessions.insert(token.clone(), session);

    if req.role == AuthRole::Validator {
        let _ = crate::db::queries::upsert_validator(&state.db, &req.hotkey, 0).await;
    }

    info!("Authenticated {} as {:?}", req.hotkey, req.role);

    Ok(Json(AuthResponse {
        success: true,
        token: Some(token),
        expires_at: Some(expires_at),
        error: None,
    }))
}

/// Verify an sr25519 signature from a hotkey
///
/// # Arguments
/// * `hotkey_ss58` - SS58 encoded hotkey (e.g., "5GrwvaEF...")
/// * `message` - The message that was signed
/// * `signature_hex` - Hex-encoded 64-byte sr25519 signature
///
/// # Returns
/// true if signature is valid, false otherwise
pub fn verify_signature(hotkey_ss58: &str, message: &str, signature_hex: &str) -> bool {
    // Parse hotkey from SS58
    let public = match sr25519::Public::from_ss58check(hotkey_ss58) {
        Ok(p) => p,
        Err(e) => {
            warn!("Invalid hotkey SS58 format: {} - {:?}", hotkey_ss58, e);
            return false;
        }
    };

    // Parse signature from hex
    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("Invalid signature hex format: {:?}", e);
            return false;
        }
    };

    if signature_bytes.len() != 64 {
        warn!(
            "Invalid signature length: {} (expected 64)",
            signature_bytes.len()
        );
        return false;
    }

    // Convert to sr25519 signature
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature_bytes);
    let signature = sr25519::Signature::from_raw(sig_bytes);

    // Verify signature
    let is_valid = sr25519::Pair::verify(&signature, message.as_bytes(), &public);

    if !is_valid {
        warn!(
            "Signature verification failed for hotkey: {}",
            &hotkey_ss58[..16.min(hotkey_ss58.len())]
        );
    }

    is_valid
}
