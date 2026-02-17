use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::fmt;

#[derive(Debug)]
pub enum ChallengeError {
    Evaluation(String),
    Validation(String),
    Network(String),
    Timeout(String),
    Serialization(String),
    Storage(String),
    Internal(String),
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChallengeError::Evaluation(msg) => write!(f, "Evaluation error: {}", msg),
            ChallengeError::Validation(msg) => write!(f, "Validation error: {}", msg),
            ChallengeError::Network(msg) => write!(f, "Network error: {}", msg),
            ChallengeError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            ChallengeError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            ChallengeError::Storage(msg) => write!(f, "Storage error: {}", msg),
            ChallengeError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl From<Box<bincode::ErrorKind>> for ChallengeError {
    fn from(err: Box<bincode::ErrorKind>) -> Self {
        ChallengeError::Serialization(format!("{}", err))
    }
}
