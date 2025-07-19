// Repository interface for User entity
// Domain layer only defines the interface, implementation is in infrastructure layer

use crate::domain::entities::user::User;
use async_trait::async_trait;
use uuid::Uuid;
use std::error::Error;

/// Type alias for repository operation results
pub type RepositoryResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Interface for repository operations related to User entity
///
/// This repository defines the contract for CRUD operations and
/// domain-specific queries on User entity. Concrete implementation
/// is in the infrastructure layer.
///
/// # Implementation
///
/// ```ignore
///
/// struct UserRepositoryImpl {
///     // Specific implementation...
/// }
///
/// #[async_trait]
/// impl UserRepository for UserRepositoryImpl {
///     // Method implementation...
/// }
/// ```
#[async_trait]
pub trait UserRepository {
    /// Find User by ID
    ///
    /// # Arguments
    ///
    /// * `id` - UUID of the user to find
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<Option<User>>` - User if found or None if not exists
    async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>>;

    /// Find User by email address
    ///
    /// # Arguments
    ///
    /// * `email` - Email address of the user to find
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<Option<User>>` - User if found or None if not exists
    async fn find_by_email(&self, email: &str) -> RepositoryResult<Option<User>>;

    /// Find User by username
    ///
    /// # Arguments
    ///
    /// * `username` - Username of the user to find
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<Option<User>>` - User if found or None if not exists
    async fn find_by_username(&self, username: &str) -> RepositoryResult<Option<User>>;

    /// Save new User to repository
    ///
    /// # Arguments
    ///
    /// * `user` - User entity to be saved
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<User>` - Saved user (with ID if generated)
    async fn save(&self, user: &User) -> RepositoryResult<User>;

    /// Update existing User in repository
    ///
    /// # Arguments
    ///
    /// * `user` - User entity with changes to be saved
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<()>` - Success or error
    async fn update(&self, user: &User) -> RepositoryResult<()>;

    /// Delete User from repository
    ///
    /// # Arguments
    ///
    /// * `id` - UUID of the user to be deleted
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<()>` - Success or error
    async fn delete(&self, id: Uuid) -> RepositoryResult<()>;

    /// Find all active Users
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<Vec<User>>` - List of active Users
    async fn find_active_users(&self) -> RepositoryResult<Vec<User>>;

    /// Find Users by role
    ///
    /// # Arguments
    ///
    /// * `role_id` - UUID of the role associated with users
    ///
    /// # Returns
    ///
    /// * `RepositoryResult<Vec<User>>` - List of Users with specific role
    async fn find_users_by_role(&self, role_id: Uuid) -> RepositoryResult<Vec<User>>;
}
