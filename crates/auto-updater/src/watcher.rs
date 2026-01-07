//! Version watcher - monitors network for required version changes

use crate::{UpdateRequirement, UpdateStatus, Version};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::info;

/// Watches for version updates from the network
#[allow(dead_code)]
pub struct VersionWatcher {
    current_version: Version,
    required_version: Arc<RwLock<Option<UpdateRequirement>>>,
    update_sender: broadcast::Sender<UpdateRequirement>,
    check_interval: Duration,
}

impl VersionWatcher {
    pub fn new(check_interval: Duration) -> Self {
        let (update_sender, _) = broadcast::channel(16);

        Self {
            current_version: Version::current(),
            required_version: Arc::new(RwLock::new(None)),
            update_sender,
            check_interval,
        }
    }

    /// Subscribe to update notifications
    pub fn subscribe(&self) -> broadcast::Receiver<UpdateRequirement> {
        self.update_sender.subscribe()
    }

    /// Called when network state updates with new version requirement
    pub fn on_version_update(&self, requirement: UpdateRequirement) {
        let current_required = self.required_version.read().clone();

        // Check if this is a new requirement
        let is_new = current_required
            .as_ref()
            .map(|r| r.min_version != requirement.min_version)
            .unwrap_or(true);

        if is_new {
            info!(
                current = %self.current_version,
                required = %requirement.min_version,
                mandatory = requirement.mandatory,
                "New version requirement received"
            );

            *self.required_version.write() = Some(requirement.clone());

            // Notify subscribers
            let _ = self.update_sender.send(requirement);
        }
    }

    /// Get current update status
    pub fn status(&self) -> UpdateStatus {
        let Some(requirement) = self.required_version.read().clone() else {
            return UpdateStatus::UpToDate;
        };

        if !self.current_version.needs_update(&requirement.min_version) {
            return UpdateStatus::UpToDate;
        }

        if requirement.mandatory {
            UpdateStatus::UpdateRequired {
                version: requirement.recommended_version,
                deadline_block: requirement.deadline_block,
            }
        } else {
            UpdateStatus::UpdateAvailable {
                version: requirement.recommended_version,
            }
        }
    }

    /// Check if update is required
    pub fn needs_update(&self) -> bool {
        matches!(
            self.status(),
            UpdateStatus::UpdateRequired { .. } | UpdateStatus::UpdateAvailable { .. }
        )
    }

    /// Check if update is mandatory
    pub fn is_mandatory(&self) -> bool {
        matches!(self.status(), UpdateStatus::UpdateRequired { .. })
    }

    /// Get required version info
    pub fn get_requirement(&self) -> Option<UpdateRequirement> {
        self.required_version.read().clone()
    }

    /// Get current version
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }
}

/// Builder for VersionWatcher
pub struct VersionWatcherBuilder {
    check_interval: Duration,
}

impl VersionWatcherBuilder {
    pub fn new() -> Self {
        Self {
            check_interval: Duration::from_secs(60),
        }
    }

    pub fn check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    pub fn build(self) -> VersionWatcher {
        VersionWatcher::new(self.check_interval)
    }
}

impl Default for VersionWatcherBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_requirement(major: u32, minor: u32, patch: u32, mandatory: bool) -> UpdateRequirement {
        let version = Version::new(major, minor, patch);
        UpdateRequirement {
            min_version: version.clone(),
            recommended_version: version,
            docker_image: "cortexlm/validator:latest".to_string(),
            mandatory,
            deadline_block: None,
            release_notes: None,
        }
    }

    #[test]
    fn test_watcher_initial_status() {
        let watcher = VersionWatcher::new(Duration::from_secs(60));
        assert_eq!(watcher.status(), UpdateStatus::UpToDate);
        assert!(!watcher.needs_update());
    }

    #[test]
    fn test_watcher_current_version_accessor() {
        let watcher = VersionWatcher::new(Duration::from_secs(60));
        assert_eq!(watcher.current_version(), &Version::current());
    }

    #[test]
    fn test_watcher_builder_custom_interval() {
        let watcher = VersionWatcherBuilder::new()
            .check_interval(Duration::from_secs(10))
            .build();
        assert_eq!(watcher.check_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_watcher_builder_default() {
        let watcher = VersionWatcherBuilder::default().build();
        assert_eq!(watcher.check_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_watcher_status_up_to_date_after_equal_requirement() {
        let watcher = VersionWatcher::new(Duration::from_secs(60));
        let requirement = UpdateRequirement {
            min_version: watcher.current_version().clone(),
            recommended_version: watcher.current_version().clone(),
            docker_image: "same".to_string(),
            mandatory: false,
            deadline_block: None,
            release_notes: None,
        };
        watcher.on_version_update(requirement);
        assert_eq!(watcher.status(), UpdateStatus::UpToDate);
    }

    #[test]
    fn test_watcher_update_available() {
        let watcher = VersionWatcher::new(Duration::from_secs(60));

        // Set a higher required version (non-mandatory)
        let requirement = make_requirement(99, 0, 0, false);
        watcher.on_version_update(requirement);

        assert!(watcher.needs_update());
        assert!(!watcher.is_mandatory());
    }

    #[test]
    fn test_watcher_mandatory_update() {
        let watcher = VersionWatcher::new(Duration::from_secs(60));

        // Set a higher required version (mandatory)
        let requirement = make_requirement(99, 0, 0, true);
        watcher.on_version_update(requirement);

        assert!(watcher.needs_update());
        assert!(watcher.is_mandatory());
    }

    #[test]
    fn test_watcher_subscribe() {
        let watcher = VersionWatcher::new(Duration::from_secs(60));
        let mut rx = watcher.subscribe();

        let requirement = make_requirement(99, 0, 0, true);
        watcher.on_version_update(requirement.clone());

        // Should receive the update
        let received = rx.try_recv().unwrap();
        assert_eq!(received.min_version, requirement.min_version);
    }
}
