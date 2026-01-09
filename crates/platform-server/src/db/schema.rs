//! Database schema and migrations

use anyhow::Result;
use deadpool_postgres::Object;
use tracing::info;

pub async fn run_migrations(client: &Object, challenge_id: &str) -> Result<()> {
    // Create tables
    client.batch_execute(SCHEMA_SQL).await?;

    // Set challenge_id in network_state
    client
        .execute(
            "UPDATE network_state SET value = $1 WHERE key = 'challenge_id'",
            &[&challenge_id],
        )
        .await?;

    info!(
        "Database migrations applied for challenge: {}",
        challenge_id
    );
    Ok(())
}

const SCHEMA_SQL: &str = r#"
-- Platform Server Database Schema
-- PostgreSQL migrations for centralized challenge management

-- Validators registered on the network
CREATE TABLE IF NOT EXISTS validators (
    hotkey VARCHAR(128) PRIMARY KEY,
    stake BIGINT NOT NULL DEFAULT 0,
    last_seen TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Challenge configuration (subnet owner can update)
CREATE TABLE IF NOT EXISTS challenge_config (
    id VARCHAR(64) PRIMARY KEY DEFAULT 'term-bench',
    name VARCHAR(255) NOT NULL,
    description TEXT,
    -- Mechanism ID for Bittensor (each challenge = one mechanism)
    mechanism_id SMALLINT NOT NULL DEFAULT 1,
    -- Emission weight (0.0 - 1.0), remaining goes to UID 0 (burn)
    emission_weight DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    -- Challenge version
    version VARCHAR(32) DEFAULT '1.0.0',
    -- Challenge status (active, paused, deprecated)
    status VARCHAR(32) DEFAULT 'active',
    max_agents_per_epoch DOUBLE PRECISION DEFAULT 0.5,
    min_stake BIGINT DEFAULT 100000000000,
    module_whitelist JSONB,
    model_whitelist JSONB,
    pricing_config JSONB,
    evaluation_config JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(128)
);

-- Agent submissions from miners
CREATE TABLE IF NOT EXISTS submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_hash VARCHAR(128) NOT NULL UNIQUE,
    miner_hotkey VARCHAR(128) NOT NULL,
    source_code TEXT,
    source_hash VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    version VARCHAR(32) DEFAULT '1.0.0',
    epoch BIGINT NOT NULL,
    status VARCHAR(32) DEFAULT 'pending',
    -- Miner's API key for LLM inferences (centralized cost tracking)
    api_key TEXT,
    -- API provider: openrouter, chutes, openai, anthropic, grok
    api_provider VARCHAR(32) DEFAULT 'openrouter',
    -- Total cost accumulated for this submission in USD
    total_cost_usd DOUBLE PRECISION DEFAULT 0.0,
    -- Deprecated: encrypted API keys (old system)
    api_keys_encrypted TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_submissions_miner ON submissions(miner_hotkey);
CREATE INDEX IF NOT EXISTS idx_submissions_epoch ON submissions(epoch);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_created ON submissions(created_at DESC);

-- Evaluation results from validators
CREATE TABLE IF NOT EXISTS evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    agent_hash VARCHAR(128) NOT NULL,
    validator_hotkey VARCHAR(128) NOT NULL,
    score DOUBLE PRECISION NOT NULL,
    tasks_passed INTEGER DEFAULT 0,
    tasks_total INTEGER DEFAULT 0,
    tasks_failed INTEGER DEFAULT 0,
    total_cost_usd DOUBLE PRECISION DEFAULT 0.0,
    execution_time_ms BIGINT,
    task_results JSONB,
    execution_log TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(submission_id, validator_hotkey)
);

CREATE INDEX IF NOT EXISTS idx_evaluations_agent ON evaluations(agent_hash);
CREATE INDEX IF NOT EXISTS idx_evaluations_validator ON evaluations(validator_hotkey);
CREATE INDEX IF NOT EXISTS idx_evaluations_created ON evaluations(created_at DESC);

-- Consensus leaderboard (computed from evaluations)
CREATE TABLE IF NOT EXISTS leaderboard (
    agent_hash VARCHAR(128) PRIMARY KEY,
    miner_hotkey VARCHAR(128) NOT NULL,
    name VARCHAR(255),
    consensus_score DOUBLE PRECISION NOT NULL,
    evaluation_count INTEGER DEFAULT 0,
    rank INTEGER,
    first_epoch BIGINT,
    last_epoch BIGINT,
    best_rank INTEGER,
    total_rewards DOUBLE PRECISION DEFAULT 0.0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_leaderboard_rank ON leaderboard(rank);
CREATE INDEX IF NOT EXISTS idx_leaderboard_score ON leaderboard(consensus_score DESC);
CREATE INDEX IF NOT EXISTS idx_leaderboard_miner ON leaderboard(miner_hotkey);

-- Task leases for Claim/Lease anti-duplication mechanism
CREATE TABLE IF NOT EXISTS task_leases (
    task_id VARCHAR(128) PRIMARY KEY,
    validator_hotkey VARCHAR(128) NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(32) DEFAULT 'active',
    ack_at TIMESTAMPTZ,
    fail_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_task_leases_validator ON task_leases(validator_hotkey);
CREATE INDEX IF NOT EXISTS idx_task_leases_status ON task_leases(status);
CREATE INDEX IF NOT EXISTS idx_task_leases_expires ON task_leases(expires_at);

-- Subnet events log (for audit trail)
CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    entity_id VARCHAR(128),
    entity_type VARCHAR(64),
    payload JSONB,
    actor_hotkey VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_entity ON events(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);

-- Network state cache
CREATE TABLE IF NOT EXISTS network_state (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Registered challenges (loaded at startup, synced with validators)
CREATE TABLE IF NOT EXISTS challenges (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    docker_image VARCHAR(512) NOT NULL,
    mechanism_id SMALLINT NOT NULL DEFAULT 1,
    emission_weight DOUBLE PRECISION NOT NULL DEFAULT 0.1,
    timeout_secs INTEGER DEFAULT 3600,
    cpu_cores DOUBLE PRECISION DEFAULT 2.0,
    memory_mb INTEGER DEFAULT 4096,
    gpu_required BOOLEAN DEFAULT FALSE,
    status VARCHAR(32) DEFAULT 'active',
    endpoint VARCHAR(512),
    container_id VARCHAR(128),
    last_health_check TIMESTAMPTZ,
    is_healthy BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_challenges_status ON challenges(status);

-- Evaluation jobs queue
CREATE TABLE IF NOT EXISTS evaluation_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    agent_hash VARCHAR(128) NOT NULL,
    miner_hotkey VARCHAR(128) NOT NULL,
    source_code TEXT,
    api_key TEXT,
    api_provider VARCHAR(32),
    challenge_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'pending',
    assigned_validator VARCHAR(128),
    assigned_at TIMESTAMPTZ,
    current_task INTEGER DEFAULT 0,
    last_progress VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON evaluation_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_challenge ON evaluation_jobs(challenge_id);
CREATE INDEX IF NOT EXISTS idx_jobs_validator ON evaluation_jobs(assigned_validator);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON evaluation_jobs(created_at ASC);

-- Insert initial network state
INSERT INTO network_state (key, value) VALUES 
    ('current_epoch', '0'),
    ('current_block', '0'),
    ('total_stake', '0'),
    ('challenge_id', '')
ON CONFLICT (key) DO NOTHING;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_sql_contains_tables() {
        // Verify that the schema SQL contains all expected table definitions
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS validators"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS challenge_config"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS submissions"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS evaluations"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS leaderboard"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS task_leases"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS events"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS network_state"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS challenges"));
        assert!(SCHEMA_SQL.contains("CREATE TABLE IF NOT EXISTS evaluation_jobs"));
    }

    #[test]
    fn test_schema_sql_contains_indexes() {
        // Verify that the schema SQL contains index definitions
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_submissions_miner"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_submissions_epoch"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_evaluations_agent"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_leaderboard_rank"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_task_leases_validator"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_events_type"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_challenges_status"));
        assert!(SCHEMA_SQL.contains("CREATE INDEX IF NOT EXISTS idx_jobs_status"));
    }

    #[test]
    fn test_schema_sql_contains_initial_data() {
        // Verify initial network state data
        assert!(SCHEMA_SQL.contains("INSERT INTO network_state"));
        assert!(SCHEMA_SQL.contains("current_epoch"));
        assert!(SCHEMA_SQL.contains("current_block"));
        assert!(SCHEMA_SQL.contains("total_stake"));
        assert!(SCHEMA_SQL.contains("challenge_id"));
    }

    #[test]
    fn test_schema_sql_contains_foreign_keys() {
        // Verify foreign key relationships
        assert!(SCHEMA_SQL.contains("REFERENCES submissions(id)"));
    }

    #[test]
    fn test_schema_sql_contains_unique_constraints() {
        // Verify unique constraints
        assert!(SCHEMA_SQL.contains("UNIQUE(submission_id, validator_hotkey)"));
        assert!(SCHEMA_SQL.contains("agent_hash VARCHAR(128) NOT NULL UNIQUE"));
    }

    #[test]
    fn test_schema_sql_default_values() {
        // Verify default values are set correctly with specific column checks
        assert!(SCHEMA_SQL.contains("status VARCHAR(32) DEFAULT 'pending'"));
        assert!(SCHEMA_SQL.contains("status VARCHAR(32) DEFAULT 'active'"));
        assert!(SCHEMA_SQL.contains("is_active BOOLEAN DEFAULT TRUE"));
        assert!(SCHEMA_SQL.contains("stake BIGINT NOT NULL DEFAULT 0"));
        assert!(SCHEMA_SQL.contains("gpu_required BOOLEAN DEFAULT FALSE"));
        assert!(SCHEMA_SQL.contains("is_healthy BOOLEAN DEFAULT FALSE"));
        assert!(SCHEMA_SQL.contains("DEFAULT NOW()"));
    }

    #[test]
    fn test_schema_sql_jsonb_fields() {
        // Verify JSONB columns exist for flexible data
        assert!(SCHEMA_SQL.contains("module_whitelist JSONB"));
        assert!(SCHEMA_SQL.contains("model_whitelist JSONB"));
        assert!(SCHEMA_SQL.contains("pricing_config JSONB"));
        assert!(SCHEMA_SQL.contains("evaluation_config JSONB"));
        assert!(SCHEMA_SQL.contains("task_results JSONB"));
        assert!(SCHEMA_SQL.contains("payload JSONB"));
    }

    #[test]
    fn test_schema_sql_timestamp_fields() {
        // Verify timestamp fields are properly defined
        assert!(SCHEMA_SQL.contains("created_at TIMESTAMPTZ"));
        assert!(SCHEMA_SQL.contains("updated_at TIMESTAMPTZ"));
        assert!(SCHEMA_SQL.contains("expires_at TIMESTAMPTZ"));
        assert!(SCHEMA_SQL.contains("last_seen TIMESTAMPTZ"));
    }
}
