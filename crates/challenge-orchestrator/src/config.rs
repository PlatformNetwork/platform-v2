//! Configuration types for challenge orchestrator
//!
//! Exposes `OrchestratorConfig`, which is serializable/deserializable with
//! human-friendly duration fields (plain seconds) so it can be shared between
//! the validator process and external tooling.

use serde::{Deserialize, Serialize};
use std::time::Duration;

// Re-export ChallengeContainerConfig from core for unified type
pub use platform_core::ChallengeContainerConfig;

/// Orchestrator configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    /// Docker network name for challenge containers
    pub network_name: String,
    /// Health check interval
    #[serde(with = "humantime_serde")]
    pub health_check_interval: Duration,
    /// Grace period to give Docker before force-stopping a container
    #[serde(with = "humantime_serde")]
    pub stop_timeout: Duration,
    /// Optional registry credentials for private images
    pub registry: Option<RegistryConfig>,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            network_name: "platform-network".to_string(),
            health_check_interval: Duration::from_secs(30),
            stop_timeout: Duration::from_secs(30),
            registry: None,
        }
    }
}

/// Optional Docker registry credentials for pulling private challenge images.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub url: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Humantime serde helper
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = OrchestratorConfig::default();
        assert_eq!(config.network_name, "platform-network");
        assert_eq!(config.health_check_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_default_config_stop_timeout_and_registry() {
        let config = OrchestratorConfig::default();
        assert_eq!(config.stop_timeout, Duration::from_secs(30));
        assert!(config.registry.is_none());
    }

    #[test]
    fn test_config_serializes_durations_as_seconds() {
        let config = OrchestratorConfig {
            network_name: "custom".into(),
            health_check_interval: Duration::from_secs(45),
            stop_timeout: Duration::from_secs(120),
            registry: Some(RegistryConfig {
                url: "https://registry.example.com".into(),
                username: Some("alice".into()),
                password: Some("secret".into()),
            }),
        };

        let json = serde_json::to_value(&config).expect("serialize config");
        assert_eq!(json["health_check_interval"], 45);
        assert_eq!(json["stop_timeout"], 120);

        let round_trip: OrchestratorConfig = serde_json::from_value(json).expect("deserialize");
        assert_eq!(round_trip.health_check_interval, Duration::from_secs(45));
        assert_eq!(round_trip.stop_timeout, Duration::from_secs(120));
        assert_eq!(
            round_trip.registry.unwrap().username.as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn test_humantime_deserialize_rejects_negative_values() {
        #[derive(Debug, Deserialize)]
        struct DurationWrapper {
            #[serde(with = "super::humantime_serde")]
            value: Duration,
        }

        let err = serde_json::from_str::<DurationWrapper>(r#"{"value": -5}"#)
            .expect_err("negative durations rejected");
        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn test_humantime_serializes_large_values() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct DurationWrapper {
            #[serde(with = "super::humantime_serde")]
            value: Duration,
        }

        let original = DurationWrapper {
            value: Duration::from_secs(24 * 60 * 60),
        };
        let json = serde_json::to_string(&original).expect("serialize duration wrapper");
        assert!(json.contains("86400"));

        let round_trip: DurationWrapper =
            serde_json::from_str(&json).expect("deserialize duration wrapper");
        assert_eq!(round_trip, original);
    }
}
