//! Continuous task types shared across orchestrator components.

use crate::config::humantime_serde;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Container/image metadata for continuous tasks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuousTaskContainerSpec {
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub labels: HashMap<String, String>,
}

/// Specification for a continuous one-shot task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuousTaskSpec {
    pub id: String,
    pub prompt: String,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub container: ContinuousTaskContainerSpec,
}

/// Result of a continuous one-shot task run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuousTaskResult {
    pub need_modifications: bool,
    pub details: String,
}

/// Scheduler state for a continuous task.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContinuousTaskScheduleState {
    pub next_run_at: DateTime<Utc>,
    pub running: bool,
}
