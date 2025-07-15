// Password hasher implementation
// Infrastructure layer implementation for password security

use argon2::{password_hash, PasswordHasher};
use std::env;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordVerifier, SaltString,
    },
    Argon2,
};
use thiserror::Error;
use log::{debug, error};

/// Errors that can occur during password operations
#[derive(Debug, Error)]
pub enum PasswordError {
    /// Error when hashing password
    #[error("Error hashing password: {0}")]
    HashingError(String),

    /// Error when verifying password
    #[error("Error verifying password: {0}")]
    VerificationError(String),
}

/// Result type for password operations
pub type PasswordResult<T> = Result<T, PasswordError>;

/// Service for password security operations
pub struct HasherPasswordService;

impl HasherPasswordService {
    /// Creates a new PasswordHasher instance
    pub fn new() -> Self {
        Self {}
    }

    /// Hashes a plaintext password
    ///
    /// # Arguments
    ///
    /// * `password` - Plaintext password to be hashed
    ///
    /// # Returns
    ///
    /// * `PasswordResult<String>` - Password hash if successful
    pub fn hash(&self, password: &str) -> PasswordResult<String> {
        // Generate a random salt
        let salt = SaltString::generate(&mut OsRng);

        // Hash password
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                error!("Failed to hash password: {}", e);
                PasswordError::HashingError(e.to_string())
            })?;

        Ok(password_hash.to_string())
    }

    /// Verifies a plaintext password against a password hash
    ///
    /// # Arguments
    ///
    /// * `password` - Plaintext password to verify
    /// * `hash` - Stored password hash
    ///
    /// # Returns
    ///
    /// * `PasswordResult<bool>` - True if password is valid, false if not
    pub fn verify_password(&self, password: &str, hash: &str) -> PasswordResult<bool> {
        // Parse hash
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| {
                error!("Failed to parse password hash: {}", e);
                PasswordError::VerificationError(e.to_string())
            })?;

        // Verify password
        let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

        match result {
            Ok(_) => Ok(true),
            Err(password_hash::Error::Password) => Ok(false), // Password doesn't match, not an error
            Err(e) => {
                error!("Error during password verification: {}", e);
                Err(PasswordError::VerificationError(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        // Arrange
        let hasher = HasherPasswordService::new();
        let password = "SecurePassword123";

        // Act
        let hash = hasher.hash(password).expect("Hashing should succeed");
        let valid = hasher.verify_password(password, &hash).expect("Verification should succeed");
        let invalid = hasher.verify_password("WrongPassword", &hash).expect("Verification should succeed");

        // Assert
        assert!(valid, "Password verification should return true for correct password");
        assert!(!invalid, "Password verification should return false for incorrect password");
    }

    #[test]
    fn test_different_passwords_have_different_hashes() {
        // Arrange
        let hasher = HasherPasswordService::new();
        let password1 = "Password123";
        let password2 = "Password123";

        // Act
        let hash1 = hasher.hash(password1).expect("Hashing should succeed");
        let hash2 = hasher.hash(password2).expect("Hashing should succeed");

        // Assert
        assert_ne!(hash1, hash2, "Different hash invocations should produce different hashes due to random salt");
    }

    #[test]
    fn test_invalid_hash_format() {
        // Arrange
        let hasher = HasherPasswordService::new();
        let password = "Password123";
        let invalid_hash = "this-is-not-a-valid-hash-format";

        // Act
        let result = hasher.verify_password(password, invalid_hash);

        // Assert
        assert!(result.is_err(), "Verification with invalid hash format should return an error");
    }
}
