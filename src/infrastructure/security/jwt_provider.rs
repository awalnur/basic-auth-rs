// JWT Provider implementation for TokenService
// Infrastructure layer implementation for token management

use crate::application::ports::token_port::{TokenService, TokenResult, TokenError};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{debug, error};

/// JWT claims for authentication
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject (user ID)
    sub: String,
    /// Issued at (time token was created)
    iat: i64,
    /// Expiry time
    exp: i64,
}

/// TokenService implementation using JWT
pub struct JwtProvider {
    secret: String,
}

impl JwtProvider {
    /// Creates a new JwtProvider instance
    pub fn new() -> Self {
        // Get secret from environment variable
        let secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| {
                debug!("JWT_SECRET not set, using default secret (not secure for production)");
                "default_jwt_secret_not_secure".to_string()
            });

        Self { secret }
    }

    /// Creates a new instance with custom secret (for testing)
    #[cfg(test)]
    pub fn with_secret(secret: &str) -> Self {
        Self { secret: secret.to_string() }
    }

    /// Gets current time in Unix timestamp
    fn current_timestamp(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64
    }
}

impl TokenService for JwtProvider {
    fn generate_token(&self, user_id: &str, expires_at: i64) -> TokenResult<String> {
        let claims = Claims {
            sub: user_id.to_string(),
            iat: self.current_timestamp(),
            exp: expires_at,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
            .map_err(|e| {
                error!("Failed to generate JWT token: {}", e);
                TokenError::GenerationError(e.to_string())
            })
    }

    fn validate_token(&self, token: &str) -> TokenResult<String> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )
            .map_err(|e| {
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::ExpiredToken,
                    _ => {
                        error!("Token validation error: {}", e);
                        TokenError::InvalidToken
                    }
                }
            })?;

        Ok(token_data.claims.sub)
    }

    fn get_user_id_from_token(&self, token: &str) -> TokenResult<String> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::new(jsonwebtoken::Algorithm::HS256),
        )
            .map_err(|e| {
                error!("Failed to extract user ID from token: {}", e);
                TokenError::InvalidToken
            })?;

        Ok(token_data.claims.sub)
    }
}
