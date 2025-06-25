use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{PgConnection}
use dotenv::dotenv;
use std::env;

use crate::utils::errors::AppError;
pub type DbPool = diesel::r2d2::Pool<ConnectionManager<PgConnection>>;
//
// Initialize the database pool
pub fn init_pool() -> Result<DbPool, AppError> {
    // Load the Environment variables

    dotenv().ok();
    // Get the database URL from the environment

    let database_url = env::var("DATABASE_URL").expect("DATABASE URL must be set");

    // Create a connection manager for the PostgreSQL connection
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    // Create the database pool with the connection manager

    let pool = Pool::builder()
        .build(manager)
        .map_err(|e| AppError::ServiceUnavailable(format!("Failed to create pool: {}", e)))?;

    // Return the database pool

    pool.get().map_err(|e| AppError::ServiceUnavailable(format!("Failed to get connection from pool: {}", e)));
    Ok(pool)
}
