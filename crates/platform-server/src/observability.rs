//! Observability - Sentry Integration
//!
//! Provides Sentry error tracking (enabled via SENTRY_DSN env var)

use tracing::info;

/// Initialize Sentry if SENTRY_DSN is set
pub fn init_sentry() -> Option<sentry::ClientInitGuard> {
    let dsn = std::env::var("SENTRY_DSN").ok()?;

    if dsn.is_empty() {
        info!("Sentry DSN is empty, error tracking disabled");
        return None;
    }

    let guard = sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: std::env::var("ENVIRONMENT").ok().map(|s| s.into()),
            traces_sample_rate: 0.1, // 10% of transactions
            ..Default::default()
        },
    ));

    info!("Sentry initialized for error tracking");
    Some(guard)
}
