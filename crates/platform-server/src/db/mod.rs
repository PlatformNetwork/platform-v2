//! Database module for Platform Server

pub mod queries;
pub mod schema;

use anyhow::Result;
use deadpool_postgres::{Config, Pool, Runtime};
use tokio_postgres::NoTls;
use tracing::info;

pub type DbPool = Pool;

/// Initialize centralized server database
/// Creates platform_server database if it doesn't exist
pub async fn init_db(base_url: &str) -> Result<DbPool> {
    let db_name = "platform_server";

    // Strip trailing database name if present (e.g., /postgres)
    let base_url = base_url
        .trim_end_matches(|c: char| c != '/')
        .trim_end_matches('/');

    // Connect to postgres database to create server database if needed
    let admin_pool = create_pool(&format!("{}/postgres", base_url)).await?;
    let admin_client = admin_pool.get().await?;

    // Check if database exists
    let row = admin_client
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])
        .await?;

    if row.is_none() {
        admin_client
            .execute(&format!("CREATE DATABASE {}", db_name), &[])
            .await?;
        info!("Created database: {}", db_name);
    }

    // Connect to server database
    let server_url = format!("{}/{}", base_url, db_name);
    let pool = create_pool(&server_url).await?;

    // Run migrations
    let client = pool.get().await?;
    schema::run_migrations(&client, "server").await?;

    info!("Server database initialized: {}", db_name);
    Ok(pool)
}

async fn create_pool(database_url: &str) -> Result<DbPool> {
    let mut cfg = Config::new();
    cfg.url = Some(database_url.to_string());
    let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;
    Ok(pool)
}
