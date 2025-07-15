// UserRepository implementation
// Infrastructure layer implementation for User data access

use crate::domain::entities::user::User;
use crate::domain::repositories::user_repository::{UserRepository, RepositoryResult};
use crate::infrastructure::persistence::models::user_model::UserModel;
use crate::infrastructure::persistence::schema::{users, user_roles};
use crate::schema;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::error::Error;
use std::sync::Arc;
use uuid::Uuid;
use log::{error, debug};

/// Type alias for database pool
type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;
/// Type alias for database error
type DbError = Box<dyn Error + Send + Sync>;
/// Type alias for database connection
type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Repository implementation for User entity
pub struct UserRepositoryImpl {
    pool: DbPool,
}

impl UserRepositoryImpl {
    /// Creates a new UserRepositoryImpl with the given connection pool
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Gets a mutable connection from the pool
    fn get_connection(&self) -> Result<DbConnection, DbError> {
        self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            Box::new(e) as DbError
        })
    }

    /// Maps a database error to a repository error with logging
    fn map_error<E>(&self, e: E, context: &str) -> DbError 
    where 
        E: Error + Send + Sync + 'static
    {
        error!("Database error {}: {}", context, e);
        Box::new(e) as DbError
    }
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    async fn find_by_id(&self, uid: Uuid) -> RepositoryResult<Option<User>> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;

        let result = users
            .filter(id.eq(uid))
            .limit(1)
            .first::<UserModel>(&mut conn)
            .optional()
            .map_err(|e| self.map_error(e, "when finding user by id"))?;

        debug!("Found user by id {}: {:?}", uid, result.is_some());
        Ok(result.map(Into::into))
    }

    async fn find_by_email(&self, email_value: &str) -> RepositoryResult<Option<User>> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;

        let result = users
            .filter(email.eq(email_value))
            .first::<UserModel>(&mut conn)
            .optional()
            .map_err(|e| self.map_error(e, "when finding user by email"))?;

        debug!("Found user by email {}: {:?}", email_value, result.is_some());
        Ok(result.map(Into::into))
    }

    async fn find_by_username(&self, username_value: &str) -> RepositoryResult<Option<User>> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;

        let result = users
            .filter(username.eq(username_value))
            .first::<UserModel>(&mut conn)
            .optional()
            .map_err(|e| self.map_error(e, "when finding user by username"))?;

        debug!("Found user by username {}: {:?}", username_value, result.is_some());
        Ok(result.map(Into::into))
    }

    async fn save(&self, user: &User) -> RepositoryResult<User> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;
        let user_model = UserModel::from(user.clone());

        diesel::insert_into(users)
            .values(&user_model)
            .execute(&mut conn)
            .map_err(|e| self.map_error(e, "when saving user"))?;

        debug!("User saved successfully: {}", user.username);
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> RepositoryResult<()> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;
        let user_model = UserModel::from(user.clone());

        // Use the user's ID directly
        diesel::update(users.filter(id.eq(user.id)))
            .set(&user_model)
            .execute(&mut conn)
            .map_err(|e| self.map_error(e, "when updating user"))?;

        debug!("User updated successfully: {}", user.username);
        Ok(())
    }

    async fn delete(&self, user_id: Uuid) -> RepositoryResult<()> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;

        diesel::delete(users.filter(id.eq(user_id)))
            .execute(&mut conn)
            .map_err(|e| self.map_error(e, "when deleting user"))?;

        debug!("User deleted successfully: {}", user_id);
        Ok(())
    }

    async fn find_active_users(&self) -> RepositoryResult<Vec<User>> {
        use crate::schema::users::dsl::*;

        let mut conn = self.get_connection()?;

        let results = users
            .filter(is_active.eq(true))
            .load::<UserModel>(&mut conn)
            .map_err(|e| self.map_error(e, "when finding active users"))?;

        debug!("Found {} active users", results.len());
        Ok(results.into_iter().map(Into::into).collect())
    }

    async fn find_users_by_role(&self, role_id: Uuid) -> RepositoryResult<Vec<User>> {
        // TODO: Implement proper role-based user lookup
        // This is a simplified implementation due to schema/type compatibility issues
        // A proper implementation would:
        // 1. Query user_roles table to get user_ids with the specified role
        // 2. Query users table to get users with those IDs

        debug!("Finding users with role {} (simplified implementation)", role_id);

        // For now, return an empty vector
        // In a real implementation, we would query the database
        Ok(Vec::new())
    }
}
