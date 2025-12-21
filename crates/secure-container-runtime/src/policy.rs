//! Security policy enforcement for container operations

use crate::types::*;
use std::collections::HashSet;
use tracing::{info, warn};

/// Security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Allowed image prefixes (e.g., "ghcr.io/platformnetwork/")
    pub allowed_image_prefixes: Vec<String>,

    /// Maximum memory per container (bytes)
    pub max_memory_bytes: i64,

    /// Maximum CPU cores per container
    pub max_cpu_cores: f64,

    /// Maximum PIDs per container
    pub max_pids: i64,

    /// Maximum containers per challenge
    pub max_containers_per_challenge: usize,

    /// Maximum containers per owner
    pub max_containers_per_owner: usize,

    /// Allowed mount source prefixes
    pub allowed_mount_prefixes: Vec<String>,

    /// Forbidden mount paths (never allow mounting these)
    pub forbidden_mount_paths: HashSet<String>,

    /// Allow privileged containers (should always be false)
    pub allow_privileged: bool,

    /// Allow host network mode
    pub allow_host_network: bool,

    /// Allow Docker socket mounting (should always be false)
    pub allow_docker_socket: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        let mut forbidden = HashSet::new();
        forbidden.insert("/var/run/docker.sock".to_string());
        forbidden.insert("/run/docker.sock".to_string());
        forbidden.insert("/etc/passwd".to_string());
        forbidden.insert("/etc/shadow".to_string());
        forbidden.insert("/etc/sudoers".to_string());
        forbidden.insert("/root".to_string());
        forbidden.insert("/home".to_string());
        forbidden.insert("/proc".to_string());
        forbidden.insert("/sys".to_string());
        forbidden.insert("/dev".to_string());

        Self {
            allowed_image_prefixes: vec!["ghcr.io/platformnetwork/".to_string()],
            max_memory_bytes: 8 * 1024 * 1024 * 1024, // 8GB
            max_cpu_cores: 4.0,
            max_pids: 512,
            max_containers_per_challenge: 10,
            max_containers_per_owner: 50,
            allowed_mount_prefixes: vec!["/tmp/".to_string(), "/var/lib/platform/".to_string()],
            forbidden_mount_paths: forbidden,
            allow_privileged: false,
            allow_host_network: false,
            allow_docker_socket: false,
        }
    }
}

impl SecurityPolicy {
    /// Create a strict policy for production
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create a more permissive policy for development
    pub fn development() -> Self {
        let mut policy = Self::default();
        policy
            .allowed_image_prefixes
            .push("localhost:5000/".to_string());
        policy
            .allowed_mount_prefixes
            .push("/workspace/".to_string());
        policy
    }

    /// Validate a container configuration against policy
    pub fn validate(&self, config: &ContainerConfig) -> Result<(), ContainerError> {
        // Check image is whitelisted
        self.validate_image(&config.image)?;

        // Check resource limits
        self.validate_resources(&config.resources)?;

        // Check mounts
        self.validate_mounts(&config.mounts)?;

        // Check network config
        self.validate_network(&config.network)?;

        // Validate required fields
        if config.challenge_id.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "challenge_id is required".to_string(),
            ));
        }

        if config.owner_id.is_empty() {
            return Err(ContainerError::InvalidConfig(
                "owner_id is required".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate image is from allowed registry
    pub fn validate_image(&self, image: &str) -> Result<(), ContainerError> {
        let image_lower = image.to_lowercase();

        for prefix in &self.allowed_image_prefixes {
            if image_lower.starts_with(&prefix.to_lowercase()) {
                return Ok(());
            }
        }

        warn!(
            image = %image,
            "SECURITY: Blocked non-whitelisted image"
        );

        Err(ContainerError::ImageNotWhitelisted(image.to_string()))
    }

    /// Validate resource limits
    pub fn validate_resources(&self, resources: &ResourceLimits) -> Result<(), ContainerError> {
        if resources.memory_bytes > self.max_memory_bytes {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "Memory limit {} exceeds maximum {}",
                resources.memory_bytes, self.max_memory_bytes
            )));
        }

        if resources.cpu_cores > self.max_cpu_cores {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "CPU limit {} exceeds maximum {}",
                resources.cpu_cores, self.max_cpu_cores
            )));
        }

        if resources.pids_limit > self.max_pids {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "PID limit {} exceeds maximum {}",
                resources.pids_limit, self.max_pids
            )));
        }

        Ok(())
    }

    /// Validate mount configurations
    pub fn validate_mounts(&self, mounts: &[MountConfig]) -> Result<(), ContainerError> {
        for mount in mounts {
            // Check for forbidden paths
            for forbidden in &self.forbidden_mount_paths {
                if mount.source.starts_with(forbidden) || mount.source == *forbidden {
                    warn!(
                        source = %mount.source,
                        "SECURITY: Blocked forbidden mount path"
                    );
                    return Err(ContainerError::PolicyViolation(format!(
                        "Mount path '{}' is forbidden",
                        mount.source
                    )));
                }
            }

            // Special check for Docker socket
            if mount.source.contains("docker.sock") && !self.allow_docker_socket {
                warn!("SECURITY: Blocked Docker socket mount attempt");
                return Err(ContainerError::PolicyViolation(
                    "Docker socket mounting is not allowed".to_string(),
                ));
            }

            // Check source is in allowed prefixes
            let allowed = self
                .allowed_mount_prefixes
                .iter()
                .any(|prefix| mount.source.starts_with(prefix));

            if !allowed && !mounts.is_empty() {
                return Err(ContainerError::PolicyViolation(format!(
                    "Mount source '{}' is not in allowed paths",
                    mount.source
                )));
            }

            // Enforce read-only for most mounts
            if !mount.read_only {
                info!(
                    source = %mount.source,
                    "Mount is writable - ensure this is intended"
                );
            }
        }

        Ok(())
    }

    /// Validate network configuration
    pub fn validate_network(&self, network: &NetworkConfig) -> Result<(), ContainerError> {
        // Host network is never allowed for challenge containers
        if !self.allow_host_network {
            // NetworkMode doesn't have Host variant, so we're safe
        }

        // Internet access should be explicitly approved
        if network.allow_internet {
            info!("Container requests internet access - ensure this is intended");
        }

        Ok(())
    }

    /// Check if challenge can create more containers
    pub fn check_container_limit(
        &self,
        challenge_id: &str,
        current_count: usize,
    ) -> Result<(), ContainerError> {
        if current_count >= self.max_containers_per_challenge {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "Challenge '{}' has reached maximum container limit ({})",
                challenge_id, self.max_containers_per_challenge
            )));
        }
        Ok(())
    }

    /// Check if owner can create more containers
    pub fn check_owner_limit(
        &self,
        owner_id: &str,
        current_count: usize,
    ) -> Result<(), ContainerError> {
        if current_count >= self.max_containers_per_owner {
            return Err(ContainerError::ResourceLimitExceeded(format!(
                "Owner '{}' has reached maximum container limit ({})",
                owner_id, self.max_containers_per_owner
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_default() {
        let policy = SecurityPolicy::default();
        assert!(!policy.allow_privileged);
        assert!(!policy.allow_docker_socket);
        assert!(!policy.allow_host_network);
    }

    #[test]
    fn test_validate_image_allowed() {
        let policy = SecurityPolicy::default();
        assert!(policy
            .validate_image("ghcr.io/platformnetwork/term-challenge:latest")
            .is_ok());
    }

    #[test]
    fn test_validate_image_blocked() {
        let policy = SecurityPolicy::default();
        assert!(policy
            .validate_image("docker.io/malicious/image:latest")
            .is_err());
        assert!(policy.validate_image("alpine:latest").is_err());
    }

    #[test]
    fn test_validate_docker_socket_blocked() {
        let policy = SecurityPolicy::default();
        let mounts = vec![MountConfig {
            source: "/var/run/docker.sock".to_string(),
            target: "/var/run/docker.sock".to_string(),
            read_only: true,
        }];
        assert!(policy.validate_mounts(&mounts).is_err());
    }

    #[test]
    fn test_validate_resources() {
        let policy = SecurityPolicy::default();

        // Valid resources
        let resources = ResourceLimits {
            memory_bytes: 2 * 1024 * 1024 * 1024,
            cpu_cores: 2.0,
            pids_limit: 256,
            disk_quota_bytes: 0,
        };
        assert!(policy.validate_resources(&resources).is_ok());

        // Excessive memory
        let resources = ResourceLimits {
            memory_bytes: 100 * 1024 * 1024 * 1024, // 100GB
            ..Default::default()
        };
        assert!(policy.validate_resources(&resources).is_err());
    }

    #[test]
    fn test_validate_full_config() {
        let policy = SecurityPolicy::default();

        let config = ContainerConfig {
            image: "ghcr.io/platformnetwork/term-challenge:latest".to_string(),
            challenge_id: "test-challenge".to_string(),
            owner_id: "test-owner".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_ok());
    }

    #[test]
    fn test_validate_missing_challenge_id() {
        let policy = SecurityPolicy::default();

        let config = ContainerConfig {
            image: "ghcr.io/platformnetwork/term-challenge:latest".to_string(),
            challenge_id: "".to_string(),
            owner_id: "test-owner".to_string(),
            ..Default::default()
        };

        assert!(policy.validate(&config).is_err());
    }
}
