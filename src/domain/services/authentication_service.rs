// Domain service for authentication
// Contains business logic involving multiple entities or value objects

use crate::domain::entities::user::User;
use crate::domain::repositories::user_repository::{UserRepository, RepositoryResult};
use thiserror::Error;
use std::sync::Arc;
use log::error;

/// Errors that may occur during authentication process
#[derive(Debug, Error)]
pub enum AuthenticationError {
    /// Invalid credentials (username/email or password)
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// User account is inactive (disabled)
    #[error("Inactive account")]
    InactiveAccount,

    /// User email is not verified
    #[error("Email not verified")]
    EmailNotVerified,

    /// Error occurred in data repository
    #[error("Repository error: {0}")]
    RepositoryError(String),
}

/// Domain service for authentication operations
///
/// This service contains business logic for user authentication,
/// including credential validation, account status checking,
/// and other authentication-related domain rules.
///
/// # Examples
///
/// ```rust
/// use crate::domain::services::authentication_service::AuthenticationService;
///
/// let auth_service = AuthenticationService::new(user_repository);
/// let result = auth_service.authenticate_user("user@example.com", "password").await;
/// ```
///
pub struct AuthenticationService {
    user_repository: Arc<dyn UserRepository + Send + Sync>,
}

impl AuthenticationService {
    /// Creates a new instance of AuthenticationService
    ///
    /// # Arguments
    ///
    /// * `user_repository` - Repository for accessing user data
    pub fn new(user_repository: Arc<dyn UserRepository + Send + Sync>) -> Self {
        Self { user_repository }
    }

    /// Authenticates user based on username/email and password
    ///
    /// Authentication process includes:
    /// 1. Finding user by username or email
    /// 2. Password verification
    /// 3. Account status validation (active and email verified)
    ///
    /// # Arguments
    ///
    /// * `username_or_email` - User's username or email
    /// * `password` - Plaintext password to be verified
    ///
    /// # Returns
    ///
    /// * `Result<User, AuthenticationError>` - Authenticated user or error
    ///
    /// # Errors
    ///
    /// * `AuthenticationError::InvalidCredentials` - If user not found or password incorrect
    /// * `AuthenticationError::InactiveAccount` - If user account is inactive
    /// * `AuthenticationError::EmailNotVerified` - If user email is not verified
    /// * `AuthenticationError::RepositoryError` - If repository error occurs
    pub async fn authenticate(
        &self,
        username_or_email: &str,
        password: &str,
    ) -> Result<User, AuthenticationError> {
        // Find user by username or email
        let user = if username_or_email.contains('@') {
            self.user_repository
                .find_by_email(username_or_email)
                .await
                .map_err(|e| {
                    error!("Repository error during authentication: {}", e);
                    AuthenticationError::RepositoryError(e.to_string())
                })?
        } else {
            self.user_repository
                .find_by_username(username_or_email)
                .await
                .map_err(|e| {
                    error!("Repository error during authentication: {}", e);
                    AuthenticationError::RepositoryError(e.to_string())
                })?
        };

        // Validate user found
        let user = user.ok_or(AuthenticationError::InvalidCredentials)?;

        // Validate user is active
        if !user.is_active {
            return Err(AuthenticationError::InactiveAccount);
        }

        // Validate password - actual implementation will use password hasher
        if !verify_password(password, &user.password_hash) {
            // Log failed login attempt (can be added later)
            // log::info!("Failed login attempt for user: {}", username_or_email);
            return Err(AuthenticationError::InvalidCredentials);
        }

        Ok(user)
    }
}

/// Helper function for password verification
///
/// # Note
///
/// This is a dummy implementation. In actual implementation, this function
/// should use secure hash algorithms like bcrypt or argon2.
///
/// # Arguments
///
/// * `password` - Plaintext password to be verified
/// * `password_hash` - Stored password hash
///
/// # Returns
///
/// * `bool` - true if password is valid, false if not
fn verify_password(password: &str, password_hash: &str) -> bool {
    // IMPORTANT: This is just a simple example, in actual implementation
    // use secure hash libraries like bcrypt or argon2
    
    password_hash == format!("hashed:{}", password)
}
