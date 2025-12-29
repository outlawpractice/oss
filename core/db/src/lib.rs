//! Database utilities for Q SDK
//!
//! Provides PostgreSQL connection pool initialization and utilities.
#![warn(missing_docs)]

#[cfg(feature = "postgres")]
use sqlx::postgres::PgPoolOptions;
#[cfg(feature = "postgres")]
use sqlx::PgPool;
use std::time::Duration;

/// Initialize a PostgreSQL connection pool from environment variables.
///
/// Reads configuration from:
/// - `DATABASE_URL` - Full connection string (preferred)
/// - Or individual variables: `PGUSER`, `PGPASSWORD`, `PGHOST`, `PGPORT`, `PGDATABASE`, `PGSSLMODE`
///
/// # Panics
///
/// Panics if required environment variables are not set or connection fails.
#[cfg(feature = "postgres")]
pub async fn initialize_database() -> PgPool {
    let db_connection_str = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        let user = std::env::var("PGUSER").expect("PGUSER not set");
        let passwd = std::env::var("PGPASSWORD").expect("PGPASSWORD not set");
        let db = std::env::var("PGDATABASE").expect("PGDATABASE not set");
        let host = std::env::var("PGHOST").expect("PGHOST not set");
        let port = std::env::var("PGPORT").unwrap_or_else(|_| "5432".to_string());
        let ssl_mode = std::env::var("PGSSLMODE").unwrap_or_else(|_| "prefer".to_string());

        format!("postgresql://{user}:{passwd}@{host}:{port}/{db}?sslmode={ssl_mode}")
    });

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&db_connection_str)
        .await
        .expect("Failed to connect to database")
}

/// Initialize a PostgreSQL connection pool with custom configuration.
///
/// # Arguments
///
/// * `connection_str` - PostgreSQL connection string
/// * `max_connections` - Maximum number of connections in the pool
/// * `acquire_timeout_secs` - Timeout in seconds for acquiring a connection
#[cfg(feature = "postgres")]
pub async fn initialize_database_with_config(
    connection_str: &str,
    max_connections: u32,
    acquire_timeout_secs: u64,
) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
        .connect(connection_str)
        .await
        .expect("Failed to connect to database")
}
