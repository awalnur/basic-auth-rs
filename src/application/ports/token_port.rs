// Token service interface
// Port is an interface used by application layer
// to communicate with infrastructure

use std::error::Error;
use thiserror::Error;

/// Errors that may occur in token operations
#[derive(Debug, Error)]
pub enum TokenError {
    /// Invalid or corrupted token
    #[error("Invalid token")]
    InvalidToken,

    /// Expired token
    #[error("Token has expired")]
    ExpiredToken,

    /// Error during token generation
    #[error("Failed to generate token: {0}")]
    GenerationError(String),

    /// General error
    #[error("Token error: {0}")]
    Other(String),
}

/// Type alias for token operation results
pub type TokenResult<T> = Result<T, TokenError>;

/// Port for authentication token operations
///
/// This interface defines the contract for operations
/// related to tokens, such as JWT creation and validation.
/// Concrete implementation is in the infrastructure layer.
pub trait TokenService: Send + Sync {
    /// Generate a new authentication token
    ///
    /// # Arguments
    ///
    /// * `user_id` - User ID to be stored in the token
    /// * `expires_at` - Token expiration time (Unix timestamp)
    ///
    /// # Returns
    ///
    /// * `TokenResult<String>` - Token string if successful
    ///
    /// # Errors
    ///
    /// Returns `TokenError` if there's an issue creating the token
    fn generate_token(&self, user_id: &str, expires_at: i64) -> TokenResult<String>;

    /// Validate token and ensure it's still valid
    ///
    /// # Arguments
    ///
    /// * `token` - Token string to be validated
    ///
    /// # Returns
    ///
    /// * `TokenResult<String>` - User ID contained in the token
    ///
    /// # Errors
    ///
    /// * `TokenError::InvalidToken` - If token is invalid
    /// * `TokenError::ExpiredToken` - If token has expired
    fn validate_token(&self, token: &str) -> TokenResult<String>;

    /// Extract user ID from token without full validation
    ///
    /// # Arguments
    ///
    /// * `token` - Token string
    ///
    /// # Returns
    ///
    /// * `TokenResult<String>` - User ID contained in the token
    ///
    /// # Errors
    ///
    /// * `TokenError::InvalidToken` - If token is invalid or corrupted
    fn get_user_id_from_token(&self, token: &str) -> TokenResult<String>;
}
