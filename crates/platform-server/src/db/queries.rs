//! Database queries for Platform Server (PostgreSQL)

use crate::models::{
    ChallengeConfig, ChallengeStatus, Evaluation, EvaluationConfig, LeaderboardEntry,
    PricingConfig, Submission, SubmissionStatus, SubmitEvaluationRequest, TaskLease,
    TaskLeaseStatus, Validator,
};
use anyhow::{anyhow, Result};
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ============================================================================
// VALIDATORS
// ============================================================================

pub async fn upsert_validator(pool: &Pool, hotkey: &str, stake: u64) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO validators (hotkey, stake, last_seen, is_active)
         VALUES ($1, $2, NOW(), TRUE)
         ON CONFLICT(hotkey) DO UPDATE SET
            stake = EXCLUDED.stake,
            last_seen = EXCLUDED.last_seen,
            is_active = TRUE",
            &[&hotkey, &(stake as i64)],
        )
        .await?;
    Ok(())
}

pub async fn get_validators(pool: &Pool) -> Result<Vec<Validator>> {
    let client = pool.get().await?;
    let rows = client
        .query(
            "SELECT hotkey, stake, last_seen, is_active, created_at
         FROM validators WHERE is_active = TRUE ORDER BY stake DESC",
            &[],
        )
        .await?;

    let validators = rows
        .iter()
        .map(|row| Validator {
            hotkey: row.get(0),
            stake: row.get::<_, i64>(1) as u64,
            last_seen: row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
                .map(|dt| dt.timestamp()),
            is_active: row.get(3),
            created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(4).timestamp(),
        })
        .collect();

    Ok(validators)
}

pub async fn get_validator(pool: &Pool, hotkey: &str) -> Result<Option<Validator>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT hotkey, stake, last_seen, is_active, created_at
         FROM validators WHERE hotkey = $1",
            &[&hotkey],
        )
        .await?;

    Ok(row.map(|row| Validator {
        hotkey: row.get(0),
        stake: row.get::<_, i64>(1) as u64,
        last_seen: row
            .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
            .map(|dt| dt.timestamp()),
        is_active: row.get(3),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(4).timestamp(),
    }))
}

pub async fn get_total_stake(pool: &Pool) -> Result<u64> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT COALESCE(SUM(stake), 0)::BIGINT FROM validators WHERE is_active = TRUE",
            &[],
        )
        .await?;
    let stake: i64 = row.try_get(0).unwrap_or(0);
    Ok(stake as u64)
}

// ============================================================================
// SUBMISSIONS
// ============================================================================

pub fn compute_agent_hash(miner_hotkey: &str, source_code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(miner_hotkey.as_bytes());
    hasher.update(source_code.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn create_submission(
    pool: &Pool,
    miner_hotkey: &str,
    source_code: &str,
    name: Option<&str>,
    api_key: Option<&str>,
    api_provider: Option<&str>,
    api_keys_encrypted: Option<&str>,
    epoch: u64,
) -> Result<Submission> {
    let client = pool.get().await?;
    let agent_hash = compute_agent_hash(miner_hotkey, source_code);
    let source_hash = hex::encode(Sha256::digest(source_code.as_bytes()));
    let provider = api_provider.unwrap_or("openrouter");

    let row = client.query_one(
        "INSERT INTO submissions (agent_hash, miner_hotkey, source_code, source_hash, name, epoch, status, api_key, api_provider, api_keys_encrypted)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9)
         RETURNING id, created_at",
        &[&agent_hash, &miner_hotkey, &source_code, &source_hash, &name, &(epoch as i64), &api_key, &provider, &api_keys_encrypted],
    ).await?;

    let id: Uuid = row.get(0);
    let created_at: chrono::DateTime<chrono::Utc> = row.get(1);

    Ok(Submission {
        id: id.to_string(),
        agent_hash,
        miner_hotkey: miner_hotkey.to_string(),
        source_code: Some(source_code.to_string()),
        source_hash,
        name: name.map(|s| s.to_string()),
        version: "1.0.0".to_string(),
        epoch,
        status: SubmissionStatus::Pending,
        api_key: api_key.map(|s| s.to_string()),
        api_provider: Some(provider.to_string()),
        total_cost_usd: Some(0.0),
        api_keys_encrypted: api_keys_encrypted.map(|s| s.to_string()),
        created_at: created_at.timestamp(),
    })
}

pub async fn get_submission(pool: &Pool, id: &str) -> Result<Option<Submission>> {
    let client = pool.get().await?;
    let uuid = match Uuid::parse_str(id) {
        Ok(u) => u,
        Err(_) => return Ok(None),
    };

    let row = client.query_opt(
        "SELECT id, agent_hash, miner_hotkey, source_code, source_hash, name, version, epoch, status, api_key, api_provider, total_cost_usd, api_keys_encrypted, created_at
         FROM submissions WHERE id = $1",
        &[&uuid]
    ).await?;

    Ok(row.map(|row| Submission {
        id: row.get::<_, Uuid>(0).to_string(),
        agent_hash: row.get(1),
        miner_hotkey: row.get(2),
        source_code: row.get(3),
        source_hash: row.get(4),
        name: row.get(5),
        version: row
            .get::<_, Option<String>>(6)
            .unwrap_or_else(|| "1.0.0".to_string()),
        epoch: row.get::<_, i64>(7) as u64,
        status: SubmissionStatus::from(row.get::<_, String>(8).as_str()),
        api_key: row.get(9),
        api_provider: row.get(10),
        total_cost_usd: row.get(11),
        api_keys_encrypted: row.get(12),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
    }))
}

pub async fn get_submission_by_hash(pool: &Pool, agent_hash: &str) -> Result<Option<Submission>> {
    let client = pool.get().await?;
    let row = client.query_opt(
        "SELECT id, agent_hash, miner_hotkey, source_code, source_hash, name, version, epoch, status, api_key, api_provider, total_cost_usd, api_keys_encrypted, created_at
         FROM submissions WHERE agent_hash = $1",
        &[&agent_hash]
    ).await?;

    Ok(row.map(|row| Submission {
        id: row.get::<_, Uuid>(0).to_string(),
        agent_hash: row.get(1),
        miner_hotkey: row.get(2),
        source_code: row.get(3),
        source_hash: row.get(4),
        name: row.get(5),
        version: row
            .get::<_, Option<String>>(6)
            .unwrap_or_else(|| "1.0.0".to_string()),
        epoch: row.get::<_, i64>(7) as u64,
        status: SubmissionStatus::from(row.get::<_, String>(8).as_str()),
        api_key: row.get(9),
        api_provider: row.get(10),
        total_cost_usd: row.get(11),
        api_keys_encrypted: row.get(12),
        created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
    }))
}

pub async fn get_pending_submissions(pool: &Pool) -> Result<Vec<Submission>> {
    let client = pool.get().await?;
    let rows = client.query(
        "SELECT id, agent_hash, miner_hotkey, source_code, source_hash, name, version, epoch, status, api_key, api_provider, total_cost_usd, api_keys_encrypted, created_at
         FROM submissions WHERE status = 'pending' ORDER BY created_at ASC",
        &[]
    ).await?;

    Ok(rows
        .iter()
        .map(|row| Submission {
            id: row.get::<_, Uuid>(0).to_string(),
            agent_hash: row.get(1),
            miner_hotkey: row.get(2),
            source_code: row.get(3),
            source_hash: row.get(4),
            name: row.get(5),
            version: row
                .get::<_, Option<String>>(6)
                .unwrap_or_else(|| "1.0.0".to_string()),
            epoch: row.get::<_, i64>(7) as u64,
            status: SubmissionStatus::from(row.get::<_, String>(8).as_str()),
            api_key: row.get(9),
            api_provider: row.get(10),
            total_cost_usd: row.get(11),
            api_keys_encrypted: row.get(12),
            created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
        })
        .collect())
}

/// Update submission cost after evaluation
pub async fn update_submission_cost(pool: &Pool, id: &str, cost_usd: f64) -> Result<()> {
    let client = pool.get().await?;
    let uuid = Uuid::parse_str(id)?;
    client
        .execute(
            "UPDATE submissions SET total_cost_usd = COALESCE(total_cost_usd, 0) + $1 WHERE id = $2",
            &[&cost_usd, &uuid],
        )
        .await?;
    Ok(())
}

pub async fn update_submission_status(
    pool: &Pool,
    id: &str,
    status: SubmissionStatus,
) -> Result<()> {
    let client = pool.get().await?;
    let uuid = Uuid::parse_str(id)?;
    client
        .execute(
            "UPDATE submissions SET status = $1 WHERE id = $2",
            &[&status.to_string(), &uuid],
        )
        .await?;
    Ok(())
}

// ============================================================================
// EVALUATIONS
// ============================================================================

pub async fn create_evaluation(pool: &Pool, req: &SubmitEvaluationRequest) -> Result<Evaluation> {
    let client = pool.get().await?;
    let submission_uuid = Uuid::parse_str(&req.submission_id)?;
    let task_results_json: Option<serde_json::Value> = req.task_results.clone();

    let row = client.query_one(
        "INSERT INTO evaluations (submission_id, agent_hash, validator_hotkey, score, tasks_passed, tasks_total, tasks_failed, total_cost_usd, execution_time_ms, task_results, execution_log)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT(submission_id, validator_hotkey) DO UPDATE SET
            score = EXCLUDED.score,
            tasks_passed = EXCLUDED.tasks_passed,
            tasks_total = EXCLUDED.tasks_total,
            tasks_failed = EXCLUDED.tasks_failed,
            total_cost_usd = EXCLUDED.total_cost_usd,
            execution_time_ms = EXCLUDED.execution_time_ms,
            task_results = EXCLUDED.task_results,
            execution_log = EXCLUDED.execution_log,
            created_at = NOW()
         RETURNING id, created_at",
        &[
            &submission_uuid,
            &req.agent_hash,
            &req.validator_hotkey,
            &req.score,
            &(req.tasks_passed as i32),
            &(req.tasks_total as i32),
            &(req.tasks_failed as i32),
            &req.total_cost_usd,
            &req.execution_time_ms,
            &task_results_json,
            &req.execution_log,
        ],
    ).await?;

    let id: Uuid = row.get(0);
    let created_at: chrono::DateTime<chrono::Utc> = row.get(1);

    Ok(Evaluation {
        id: id.to_string(),
        submission_id: req.submission_id.clone(),
        agent_hash: req.agent_hash.clone(),
        validator_hotkey: req.validator_hotkey.clone(),
        score: req.score,
        tasks_passed: req.tasks_passed,
        tasks_total: req.tasks_total,
        tasks_failed: req.tasks_failed,
        total_cost_usd: req.total_cost_usd,
        execution_time_ms: req.execution_time_ms,
        task_results: task_results_json.map(|v| v.to_string()),
        execution_log: req.execution_log.clone(),
        created_at: created_at.timestamp(),
    })
}

pub async fn get_evaluations_for_agent(pool: &Pool, agent_hash: &str) -> Result<Vec<Evaluation>> {
    let client = pool.get().await?;
    let rows = client.query(
        "SELECT id, submission_id, agent_hash, validator_hotkey, score, tasks_passed, tasks_total, tasks_failed, total_cost_usd, execution_time_ms, task_results, execution_log, created_at
         FROM evaluations WHERE agent_hash = $1 ORDER BY created_at DESC",
        &[&agent_hash]
    ).await?;

    Ok(rows
        .iter()
        .map(|row| {
            let task_results: Option<serde_json::Value> = row.get(10);
            Evaluation {
                id: row.get::<_, Uuid>(0).to_string(),
                submission_id: row.get::<_, Uuid>(1).to_string(),
                agent_hash: row.get(2),
                validator_hotkey: row.get(3),
                score: row.get(4),
                tasks_passed: row.get::<_, i32>(5) as u32,
                tasks_total: row.get::<_, i32>(6) as u32,
                tasks_failed: row.get::<_, i32>(7) as u32,
                total_cost_usd: row.get(8),
                execution_time_ms: row.get(9),
                task_results: task_results.map(|v| v.to_string()),
                execution_log: row.get(11),
                created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(12).timestamp(),
            }
        })
        .collect())
}

// ============================================================================
// LEADERBOARD
// ============================================================================

pub async fn update_leaderboard(pool: &Pool, agent_hash: &str) -> Result<Option<LeaderboardEntry>> {
    let evaluations = get_evaluations_for_agent(pool, agent_hash).await?;
    if evaluations.is_empty() {
        return Ok(None);
    }

    let submission = get_submission_by_hash(pool, agent_hash)
        .await?
        .ok_or_else(|| anyhow!("Submission not found for agent_hash: {}", agent_hash))?;

    let scores: Vec<f64> = evaluations.iter().map(|e| e.score).collect();
    let consensus_score = scores.iter().sum::<f64>() / scores.len() as f64;
    let evaluation_count = evaluations.len() as i32;
    let first_epoch = submission.epoch as i64;

    let client = pool.get().await?;

    client.execute(
        "INSERT INTO leaderboard (agent_hash, miner_hotkey, name, consensus_score, evaluation_count, first_epoch, last_epoch, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT(agent_hash) DO UPDATE SET
            consensus_score = EXCLUDED.consensus_score,
            evaluation_count = EXCLUDED.evaluation_count,
            last_epoch = EXCLUDED.last_epoch,
            updated_at = EXCLUDED.updated_at",
        &[&agent_hash, &submission.miner_hotkey, &submission.name, &consensus_score, &evaluation_count, &first_epoch, &first_epoch],
    ).await?;

    // Update ranks
    client.execute(
        "UPDATE leaderboard SET rank = subq.new_rank
         FROM (SELECT agent_hash, ROW_NUMBER() OVER (ORDER BY consensus_score DESC) as new_rank FROM leaderboard) subq
         WHERE leaderboard.agent_hash = subq.agent_hash",
        &[]
    ).await?;

    get_leaderboard_entry(pool, agent_hash).await
}

pub async fn get_leaderboard_entry(
    pool: &Pool,
    agent_hash: &str,
) -> Result<Option<LeaderboardEntry>> {
    let client = pool.get().await?;
    let row = client.query_opt(
        "SELECT agent_hash, miner_hotkey, name, consensus_score, evaluation_count, rank, first_epoch, last_epoch, best_rank, total_rewards, updated_at
         FROM leaderboard WHERE agent_hash = $1",
        &[&agent_hash]
    ).await?;

    Ok(row.map(|row| LeaderboardEntry {
        agent_hash: row.get(0),
        miner_hotkey: row.get(1),
        name: row.get(2),
        consensus_score: row.get(3),
        evaluation_count: row.get::<_, i32>(4) as u32,
        rank: row.get::<_, Option<i32>>(5).unwrap_or(0) as u32,
        first_epoch: row.get::<_, i64>(6) as u64,
        last_epoch: row.get::<_, i64>(7) as u64,
        best_rank: row.get::<_, Option<i32>>(8).map(|r| r as u32),
        total_rewards: row.get(9),
        updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(10).timestamp(),
    }))
}

pub async fn get_leaderboard(pool: &Pool, limit: usize) -> Result<Vec<LeaderboardEntry>> {
    let client = pool.get().await?;
    let rows = client.query(
        "SELECT agent_hash, miner_hotkey, name, consensus_score, evaluation_count, rank, first_epoch, last_epoch, best_rank, total_rewards, updated_at
         FROM leaderboard ORDER BY rank ASC NULLS LAST LIMIT $1",
        &[&(limit as i64)]
    ).await?;

    Ok(rows
        .iter()
        .map(|row| LeaderboardEntry {
            agent_hash: row.get(0),
            miner_hotkey: row.get(1),
            name: row.get(2),
            consensus_score: row.get(3),
            evaluation_count: row.get::<_, i32>(4) as u32,
            rank: row.get::<_, Option<i32>>(5).unwrap_or(0) as u32,
            first_epoch: row.get::<_, i64>(6) as u64,
            last_epoch: row.get::<_, i64>(7) as u64,
            best_rank: row.get::<_, Option<i32>>(8).map(|r| r as u32),
            total_rewards: row.get(9),
            updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(10).timestamp(),
        })
        .collect())
}

// ============================================================================
// CHALLENGE CONFIG
// ============================================================================

pub async fn get_challenge_config(pool: &Pool, id: &str) -> Result<Option<ChallengeConfig>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT id, name, description, mechanism_id, emission_weight, version, status,
                max_agents_per_epoch, min_stake, module_whitelist, model_whitelist, 
                pricing_config, evaluation_config, updated_at, updated_by
         FROM challenge_config WHERE id = $1",
            &[&id],
        )
        .await?;

    Ok(row.map(|row| {
        let module_whitelist: Option<serde_json::Value> = row.get(9);
        let model_whitelist: Option<serde_json::Value> = row.get(10);
        let pricing_config: Option<serde_json::Value> = row.get(11);
        let evaluation_config: Option<serde_json::Value> = row.get(12);
        let status_str: String = row.get(6);

        ChallengeConfig {
            id: row.get(0),
            name: row.get(1),
            description: row.get(2),
            mechanism_id: row.get::<_, i16>(3) as u8,
            emission_weight: row.get(4),
            version: row
                .get::<_, Option<String>>(5)
                .unwrap_or_else(|| "1.0.0".to_string()),
            status: match status_str.as_str() {
                "paused" => ChallengeStatus::Paused,
                "deprecated" => ChallengeStatus::Deprecated,
                _ => ChallengeStatus::Active,
            },
            max_agents_per_epoch: row.get(7),
            min_stake: row.get::<_, i64>(8) as u64,
            module_whitelist: module_whitelist.and_then(|v| serde_json::from_value(v).ok()),
            model_whitelist: model_whitelist.and_then(|v| serde_json::from_value(v).ok()),
            pricing_config: pricing_config.and_then(|v| serde_json::from_value(v).ok()),
            evaluation_config: evaluation_config.and_then(|v| serde_json::from_value(v).ok()),
            updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(13).timestamp(),
            updated_by: row.get(14),
        }
    }))
}

pub async fn update_challenge_config(
    pool: &Pool,
    id: &str,
    config: &serde_json::Value,
    updated_by: &str,
) -> Result<()> {
    let client = pool.get().await?;

    if let Some(name) = config.get("name").and_then(|v| v.as_str()) {
        client.execute("UPDATE challenge_config SET name = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3",
            &[&name, &updated_by, &id]).await?;
    }
    if let Some(max_agents) = config.get("max_agents_per_epoch").and_then(|v| v.as_f64()) {
        client.execute("UPDATE challenge_config SET max_agents_per_epoch = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3",
            &[&max_agents, &updated_by, &id]).await?;
    }
    if let Some(modules) = config.get("module_whitelist") {
        client.execute("UPDATE challenge_config SET module_whitelist = $1, updated_at = NOW(), updated_by = $2 WHERE id = $3",
            &[&modules, &updated_by, &id]).await?;
    }

    Ok(())
}

// ============================================================================
// NETWORK STATE
// ============================================================================

pub async fn get_network_state(pool: &Pool, key: &str) -> Result<Option<String>> {
    let client = pool.get().await?;
    let row = client
        .query_opt("SELECT value FROM network_state WHERE key = $1", &[&key])
        .await?;
    Ok(row.map(|r| r.get(0)))
}

pub async fn set_network_state(pool: &Pool, key: &str, value: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO network_state (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
            &[&key, &value],
        )
        .await?;
    Ok(())
}

pub async fn get_current_epoch(pool: &Pool) -> Result<u64> {
    let value = get_network_state(pool, "current_epoch")
        .await?
        .unwrap_or_else(|| "0".to_string());
    Ok(value.parse().unwrap_or(0))
}

// ============================================================================
// TASK LEASES (Claim/Lease)
// ============================================================================

pub async fn claim_task(
    pool: &Pool,
    task_id: &str,
    validator_hotkey: &str,
    ttl_seconds: u64,
) -> Result<Option<TaskLease>> {
    let client = pool.get().await?;

    // Check if task is already claimed and not expired
    let existing = client.query_opt(
        "SELECT validator_hotkey, expires_at FROM task_leases WHERE task_id = $1 AND status = 'active' AND expires_at > NOW()",
        &[&task_id]
    ).await?;

    if let Some(row) = existing {
        let holder: String = row.get(0);
        if holder != validator_hotkey {
            return Ok(None); // Already claimed by another validator
        }
    }

    // Upsert lease
    let row = client
        .query_one(
            "INSERT INTO task_leases (task_id, validator_hotkey, claimed_at, expires_at, status)
         VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 second' * $3, 'active')
         ON CONFLICT(task_id) DO UPDATE SET
            validator_hotkey = EXCLUDED.validator_hotkey,
            claimed_at = EXCLUDED.claimed_at,
            expires_at = EXCLUDED.expires_at,
            status = 'active'
         RETURNING claimed_at, expires_at",
            &[&task_id, &validator_hotkey, &(ttl_seconds as f64)],
        )
        .await?;

    let claimed_at: chrono::DateTime<chrono::Utc> = row.get(0);
    let expires_at: chrono::DateTime<chrono::Utc> = row.get(1);

    Ok(Some(TaskLease {
        task_id: task_id.to_string(),
        validator_hotkey: validator_hotkey.to_string(),
        claimed_at: claimed_at.timestamp(),
        expires_at: expires_at.timestamp(),
        status: TaskLeaseStatus::Active,
    }))
}

pub async fn renew_task(
    pool: &Pool,
    task_id: &str,
    validator_hotkey: &str,
    ttl_seconds: u64,
) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute(
            "UPDATE task_leases SET expires_at = NOW() + INTERVAL '1 second' * $1
         WHERE task_id = $2 AND validator_hotkey = $3 AND status = 'active'",
            &[&(ttl_seconds as f64), &task_id, &validator_hotkey],
        )
        .await?;
    Ok(result > 0)
}

pub async fn ack_task(pool: &Pool, task_id: &str, validator_hotkey: &str) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute(
            "UPDATE task_leases SET status = 'completed', ack_at = NOW()
         WHERE task_id = $1 AND validator_hotkey = $2 AND status = 'active'",
            &[&task_id, &validator_hotkey],
        )
        .await?;
    Ok(result > 0)
}

pub async fn fail_task(
    pool: &Pool,
    task_id: &str,
    validator_hotkey: &str,
    reason: Option<&str>,
) -> Result<bool> {
    let client = pool.get().await?;
    let result = client
        .execute(
            "UPDATE task_leases SET status = 'failed', fail_reason = $1
         WHERE task_id = $2 AND validator_hotkey = $3 AND status = 'active'",
            &[&reason, &task_id, &validator_hotkey],
        )
        .await?;
    Ok(result > 0)
}

pub async fn log_event(
    pool: &Pool,
    event_type: &str,
    entity_type: Option<&str>,
    entity_id: Option<&str>,
    payload: Option<&str>,
    actor: Option<&str>,
) -> Result<()> {
    let client = pool.get().await?;
    let payload_json: Option<serde_json::Value> =
        payload.and_then(|s| serde_json::from_str(s).ok());
    client.execute(
        "INSERT INTO events (event_type, entity_type, entity_id, payload, actor_hotkey) VALUES ($1, $2, $3, $4, $5)",
        &[&event_type, &entity_type, &entity_id, &payload_json, &actor],
    ).await?;
    Ok(())
}
