//! Version management

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

/// Semantic version
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Current validator version (compile-time)
    pub fn current() -> Self {
        Self {
            major: platform_core::PROTOCOL_VERSION_MAJOR,
            minor: platform_core::PROTOCOL_VERSION_MINOR,
            patch: platform_core::PROTOCOL_VERSION_PATCH,
        }
    }

    /// Parse from string (e.g., "0.1.0")
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim_start_matches('v').split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
        })
    }

    /// Check if this version is compatible with a minimum required version
    pub fn is_compatible_with(&self, min_version: &Version) -> bool {
        self >= min_version
    }

    /// Check if update is available
    pub fn needs_update(&self, required: &Version) -> bool {
        self < required
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                ord => ord,
            },
            ord => ord,
        }
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::current()
    }
}

/// Update requirements from network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateRequirement {
    /// Minimum required version
    pub min_version: Version,
    /// Recommended version (latest stable)
    pub recommended_version: Version,
    /// Docker image for the update
    pub docker_image: String,
    /// Whether update is mandatory (disconnect if not updated)
    pub mandatory: bool,
    /// Deadline for mandatory update (Bittensor block height)
    pub deadline_block: Option<u64>,
    /// Release notes
    pub release_notes: Option<String>,
}

/// Update status
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateStatus {
    /// Running latest version
    UpToDate,
    /// Update available but not mandatory
    UpdateAvailable { version: Version },
    /// Mandatory update required
    UpdateRequired {
        version: Version,
        deadline_block: Option<u64>,
    },
    /// Version check in progress
    Checking,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);

        let v = Version::parse("v0.1.0").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_default_matches_current() {
        assert_eq!(Version::default(), Version::current());
    }

    #[test]
    fn test_version_parse_invalid_inputs() {
        assert!(Version::parse("1.2").is_none());
        assert!(Version::parse("1.2.3.4").is_none());
        assert!(Version::parse("a.b.c").is_none());
    }

    #[test]
    fn test_version_display() {
        let v = Version::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
    }

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(0, 1, 0);
        let v2 = Version::new(0, 2, 0);
        let v3 = Version::new(1, 0, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);
    }

    #[test]
    fn test_version_compatibility() {
        let current = Version::new(0, 2, 0);
        let min = Version::new(0, 1, 0);
        let future = Version::new(0, 3, 0);

        assert!(current.is_compatible_with(&min));
        assert!(!current.is_compatible_with(&future));
    }

    #[test]
    fn test_needs_update() {
        let current = Version::new(0, 1, 0);
        let required = Version::new(0, 2, 0);

        assert!(current.needs_update(&required));
        assert!(!required.needs_update(&current));
    }
}
